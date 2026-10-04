import json
import os
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

import httpx
import jwt
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent
EVIDENCIAS = ROOT / "docs" / "evidencias"

COMMIT_INICIAL = "1d6d142"
COMMIT_ANTES = "ab4db0d"
OLD_SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
OLD_PASSWORDS = {"dr_roberto": "Doctor@123", "recepcao": "Recepcao@123"}
OLD_LAB_SECRET = "LabSecretKey2026!"
PORTS = {"inicial": 8101, "antes": 8102, "depois": 8103}

VALID_APPOINTMENT = {
    "patient_name": "Paciente Teste",
    "patient_cpf": "111.222.333-44",
    "doctor_name": "Dr. Roberto Silva",
    "doctor_crm": "CRM/SP 123456",
    "appointment_datetime": "2026-10-20T10:00:00Z",
    "specialty": "Cardiologia",
    "status": "agendada",
}


@dataclass
class Check:
    label: str
    status: int
    kind: str

    @property
    def verdict(self) -> str:
        success = 200 <= self.status < 300
        if self.kind == "controle":
            return "OK" if success else "FALHOU"
        return "EXPLORADO" if success else "BLOQUEADO"

    def line(self) -> str:
        return f"  [{self.verdict:<9}] {self.label}  -> HTTP {self.status}"


class Server:
    def __init__(self, name: str, directory: Path, port: int, env: dict[str, str]) -> None:
        self.name = name
        self.directory = directory
        self.port = port
        self.env = env
        self.process: Optional[subprocess.Popen] = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "Server":
        self.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=self.directory,
            env=self.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 40
        while time.time() < deadline:
            if self.process.poll() is not None:
                break
            try:
                if httpx.get(self.base + "/", timeout=2).status_code == 200:
                    return self
            except httpx.HTTPError:
                time.sleep(0.5)
        self.__exit__(None, None, None)
        raise SystemExit(f"servidor '{self.name}' nao subiu na porta {self.port}")

    def __exit__(self, *_exc) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()


def export_commit(commit: str, destination: Path) -> None:
    archive = subprocess.run(["git", "archive", commit], cwd=ROOT, check=True, capture_output=True).stdout
    subprocess.run(["tar", "-x", "-C", str(destination)], input=archive, check=True)


def git_output(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def clean_env() -> dict[str, str]:
    blocked = {
        "SECRET_KEY", "DATABASE_URL", "SEED_DEMO_DATA", "DEMO_USERS_PASSWORD",
        "DEMO_LAB_CLIENT_SECRET", "DEMO_ADMIN_MFA_SECRET", "ENVIRONMENT",
    }
    return {k: v for k, v in os.environ.items() if k not in blocked}


def current_env(database_dir: Path) -> dict[str, str]:
    env = clean_env()
    env.update({k: v for k, v in dotenv_values(ROOT / ".env").items() if v is not None})
    env.update({
        "DATABASE_URL": f"sqlite:///{database_dir / 'depois.db'}",
        "SEED_DEMO_DATA": "true",
        "ENVIRONMENT": "development",
    })
    return env


def forged_token(role: str, sub: str, scopes: list[str], crm: Optional[str] = None, mfa: bool = False) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": sub,
        "role": role,
        "scopes": scopes,
        "mfa_verified": mfa,
        "iat": now,
        "exp": now + timedelta(minutes=30),
    }
    if crm:
        claims["doctor_crm"] = crm
    return jwt.encode(claims, OLD_SECRET_KEY, algorithm="HS256")


def bearer(token: Optional[str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def login(client: httpx.Client, username: str, password: str) -> Optional[str]:
    response = client.post("/auth/token", data={"username": username, "password": password})
    return response.json().get("access_token") if response.status_code == 200 else None


def lab_token(client: httpx.Client, secret: str) -> Optional[str]:
    response = client.post(
        "/auth/m2m/token",
        json={"grant_type": "client_credentials", "client_id": "partner-lab-01", "client_secret": secret},
    )
    return response.json().get("access_token") if response.status_code == 200 else None


def mfa_fixed_code_status(client: httpx.Client) -> int:
    response = client.post("/auth/mfa/verify", json={"username": "admin", "mfa_code": "849201"})
    if response.status_code != 200:
        return response.status_code
    token = response.json().get("access_token")
    return client.get("/admin/audit-logs", headers=bearer(token)).status_code


def run_unauthenticated_suite(client: httpx.Client) -> list[Check]:
    return [
        Check("listar todas as consultas sem token", client.get("/appointments/").status_code, "ataque"),
        Check("BOLA: ler consulta de outro paciente (id 2) sem token", client.get("/appointments/2").status_code, "ataque"),
        Check("agenda HTML da recepcao sem token", client.get("/recepcao/agenda").status_code, "ataque"),
    ]


def run_main_suite(
    client: httpx.Client,
    passwords: dict[str, str],
    lab_secret: str,
) -> list[Check]:
    doctor = login(client, "dr_roberto", passwords["dr_roberto"])
    reception = login(client, "recepcao", passwords["recepcao"])
    lab = lab_token(client, lab_secret)
    if not (doctor and reception and lab):
        raise SystemExit("falha ao obter tokens legitimos de dr_roberto, recepcao ou laboratorio")

    def post_appointment(token: str, payload: dict) -> int:
        return client.post("/appointments/", json=payload, headers=bearer(token)).status_code

    forged_admin = forged_token("admin", "admin", ["admin:manage", "appointments:read", "appointments:write"], mfa=True)
    checks: list[Check] = [
        Check("MFA: codigo fixo 849201 sem 1o fator, depois /admin/audit-logs", mfa_fixed_code_status(client), "ataque"),
        Check(
            "JWT forjado como admin com a chave padrao do codigo antigo",
            client.get("/admin/audit-logs", headers=bearer(forged_admin)).status_code,
            "ataque",
        ),
        Check("token do laboratorio listando consultas", client.get("/appointments/", headers=bearer(lab)).status_code, "ataque"),
        Check("token do laboratorio lendo consulta por ID", client.get("/appointments/1", headers=bearer(lab)).status_code, "ataque"),
        Check("agenda HTML da recepcao sem token", client.get("/recepcao/agenda").status_code, "ataque"),
        Check("mass assignment: campo nao declarado is_admin", post_appointment(doctor, {**VALID_APPOINTMENT, "is_admin": True}), "ataque"),
        Check(
            "XSS armazenado no nome do paciente",
            post_appointment(doctor, {**VALID_APPOINTMENT, "patient_name": "<script>alert(1)</script>"}),
            "ataque",
        ),
        Check("CPF fora do padrao (invalid-cpf-1)", post_appointment(doctor, {**VALID_APPOINTMENT, "patient_cpf": "invalid-cpf-1"}), "ataque"),
        Check(
            "SQL injection em doctor_name",
            post_appointment(doctor, {**VALID_APPOINTMENT, "doctor_name": "x'); DROP TABLE users;--"}),
            "ataque",
        ),
        Check("BOLA: medico le consulta de outro medico (id 2)", client.get("/appointments/2", headers=bearer(doctor)).status_code, "ataque"),
        Check("controle: payload legitimo do medico", post_appointment(doctor, VALID_APPOINTMENT), "controle"),
        Check("recepcionista cria consulta", post_appointment(reception, VALID_APPOINTMENT), "ataque"),
        Check("recepcionista apaga consulta (id 2)", client.delete("/appointments/2", headers=bearer(reception)).status_code, "ataque"),
    ]
    return checks


def render(title: str, sections: list[tuple[str, list[Check]]], meta: list[str]) -> str:
    lines = [title, f"gerado em {datetime.now().astimezone().isoformat(timespec='seconds')}", *meta, ""]
    for heading, checks in sections:
        lines.append(f"== {heading} ==")
        lines.extend(check.line() for check in checks)
        exploited = sum(1 for c in checks if c.kind == "ataque" and c.verdict == "EXPLORADO")
        attacks = sum(1 for c in checks if c.kind == "ataque")
        lines.append(f"  resumo: {exploited} de {attacks} ataques exploraram a falha")
        lines.append("")
    return "\n".join(lines)


def comparison(before: list[Check], after: list[Check], heading: str) -> list[str]:
    rows = [f"== {heading} ==", f"  {'ataque / verificacao':<68}{'antes':<15}{'depois':<15}"]
    for old, new in zip(before, after):
        rows.append(f"  {old.label:<68}{old.verdict + ' ' + str(old.status):<15}{new.verdict + ' ' + str(new.status):<15}")
    rows.append("")
    return rows


def main() -> int:
    if not (ROOT / ".env").exists():
        raise SystemExit(".env ausente: copie .env.example e defina SECRET_KEY e as senhas de demonstracao")
    env_values = dotenv_values(ROOT / ".env")
    for key in ("SECRET_KEY", "DEMO_USERS_PASSWORD", "DEMO_LAB_CLIENT_SECRET"):
        if not env_values.get(key):
            raise SystemExit(f"{key} ausente no .env")

    head = git_output("rev-parse", "--short", "HEAD")
    dirty = " (com alteracoes nao commitadas)" if git_output("status", "--porcelain") else ""
    full_initial = git_output("rev-parse", "--short", COMMIT_INICIAL)
    full_before = git_output("rev-parse", "--short", COMMIT_ANTES)

    with tempfile.TemporaryDirectory(prefix="medsync_antes_depois_") as tmp, ExitStack() as stack:
        workdir = Path(tmp)
        initial_dir = workdir / "inicial"
        before_dir = workdir / "antes"
        initial_dir.mkdir()
        before_dir.mkdir()
        export_commit(COMMIT_INICIAL, initial_dir)
        export_commit(COMMIT_ANTES, before_dir)

        initial = stack.enter_context(Server("inicial", initial_dir, PORTS["inicial"], clean_env()))
        before = stack.enter_context(Server("antes", before_dir, PORTS["antes"], clean_env()))
        after = stack.enter_context(Server("depois", ROOT, PORTS["depois"], current_env(workdir)))

        with httpx.Client(base_url=initial.base, timeout=15) as client:
            initial_checks = run_unauthenticated_suite(client)
        with httpx.Client(base_url=before.base, timeout=15) as client:
            before_checks = run_main_suite(client, OLD_PASSWORDS, OLD_LAB_SECRET)
        with httpx.Client(base_url=after.base, timeout=15) as client:
            after_initial_checks = run_unauthenticated_suite(client)
            demo_password = env_values["DEMO_USERS_PASSWORD"] or ""
            after_checks = run_main_suite(
                client,
                {"dr_roberto": demo_password, "recepcao": demo_password},
                env_values["DEMO_LAB_CLIENT_SECRET"] or "",
            )

    EVIDENCIAS.mkdir(parents=True, exist_ok=True)
    before_text = render(
        "MedSync API - ataques ANTES das correcoes",
        [
            (f"Versao inicial {full_initial} (Ex.1 e Ex.2, sem autenticacao)", initial_checks),
            (f"Versao {full_before} (autenticacao do Ex.6 e 7, antes das correcoes do Ex.8 e 9)", before_checks),
        ],
        [f"codigo analisado: commits {full_initial} e {full_before}"],
    )
    after_text = render(
        "MedSync API - os MESMOS ataques DEPOIS das correcoes",
        [
            ("Mesmos ataques da versao inicial", after_initial_checks),
            ("Mesmos ataques da versao anterior as correcoes", after_checks),
        ],
        [f"codigo analisado: commit {head}{dirty}"],
    )
    comparison_text = "\n".join(
        [
            "MedSync API - comparativo antes x depois (mesmos ataques)",
            f"antes: {full_initial} e {full_before} | depois: {head}{dirty}",
            "",
            *comparison(initial_checks, after_initial_checks, "Versao inicial x atual"),
            *comparison(before_checks, after_checks, "Versao pre-correcao x atual"),
        ]
    )

    (EVIDENCIAS / "antes_ataques.txt").write_text(before_text + "\n", encoding="utf-8")
    (EVIDENCIAS / "depois_ataques.txt").write_text(after_text + "\n", encoding="utf-8")
    (EVIDENCIAS / "comparativo_antes_depois.txt").write_text(comparison_text + "\n", encoding="utf-8")
    print(comparison_text)

    leaked = [c for c in after_initial_checks + after_checks if c.kind == "ataque" and c.verdict == "EXPLORADO"]
    broken = [c for c in after_checks if c.kind == "controle" and c.verdict != "OK"]
    if leaked or broken:
        print("FALHA: a versao atual ainda e vulneravel ou o controle legitimo falhou", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
