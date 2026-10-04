# MedSync API — Agendamento Seguro de Consultas Médicas

API RESTful modularizada com **FastAPI**, **Pydantic** e **SQLModel** para agendamento de consultas em redes de clínicas, desenhada para dados de saúde sob a **LGPD** e para as categorias do **OWASP API Security Top 10**.

**Estudante:** Marcos Ryan

## Vídeo de apresentação (YouTube, não listado)

- **Link:** [youtube-link](https://youtu.be/0cyzDBWq-KE)
- **Backup (Drive):** [link](https://drive.google.com/file/d/1NbZpZJL85cR2zsuIglHnQMpHzZoefh7W/view?usp=drive_link)

## Relatório técnico

Ponto de entrada: [`docs/RELATORIO_TECNICO.md`](docs/RELATORIO_TECNICO.md) (decisão, código, teste e evidência de cada exercício).

| Exercícios  | Documento                                                                                                   |
| :----------- | :---------------------------------------------------------------------------------------------------------- |
| 1, 2, 6, 7   | [`docs/decisoes_ex1_ex2_ex6_ex7.md`](docs/decisoes_ex1_ex2_ex6_ex7.md)                                     |
| 3, 4, 5      | [`docs/modelagem_seguranca_ex3_ex4_ex5.md`](docs/modelagem_seguranca_ex3_ex4_ex5.md)                       |
| 8, 9, 10, 11 | [`docs/vulnerabilidades_owasp_e_correcoes_ex8_ex9.md`](docs/vulnerabilidades_owasp_e_correcoes_ex8_ex9.md) |
| 12, 13       | [`docs/relatorio_final_capstone_ex12_ex13.md`](docs/relatorio_final_capstone_ex12_ex13.md)                 |

---

## Como executar

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # preencha SECRET_KEY (openssl rand -hex 32) e, para demo, SEED_DEMO_DATA=true + senhas SUAS
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- Swagger: http://127.0.0.1:8000/docs · OpenAPI: `/openapi.json` (**desativados** com `ENVIRONMENT=production`)
- Agenda da recepção: `GET /recepcao/agenda?data=AAAA-MM-DD&limit=100&offset=0` (exige `Authorization: Bearer <token>` de recepcionista/admin)
- Código TOTP do admin de demonstração: `python scripts/gen_totp.py`

## Testes

```bash
pytest -v        # 63 testes
```

Cobrem: CRUD de consultas, `response_model`, XSS (auto-escape), bcrypt, RBAC, MFA TOTP, ownership (BOLA), OAuth2 Client Credentials e escopos, `extra='forbid'`, whitelist/regex, headers de segurança, CORS, rate limit, SQLModel, mocking de sessão, auditoria OpenAPI, regressão de cada falha corrigida e achados do ZAP.

## Pipeline DevSecOps (GitHub Actions)

`.github/workflows/security-pipeline.yml` — job **`Security Gate`**. Bloqueia se: `pip-audit --strict` achar qualquer CVE; `bandit -ll` achar severidade Medium/High; ou qualquer teste falhar. Justificativa do critério: `docs/relatorio_final_capstone_ex12_ex13.md` §1.3.

**Para o gate realmente impedir o merge**, ative a branch protection (uma vez, com o repositório no GitHub e o `gh` autenticado):

```bash
gh api -X PUT repos/<USUARIO>/<REPO>/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["Security Gate"] },
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null
}
JSON
```

## Scan OWASP ZAP (DAST, pré-release)

```bash
# API no ar (SEED_DEMO_DATA=true) em outro terminal. Docker necessário.
bash scripts/run_zap_scan.sh after                       # scan passivo AUTENTICADO -> docs/owasp_zap_after.{json,html}
python scripts/zap_gate.py docs/owasp_zap_after.json     # gate: qualquer alerta >= Medium bloqueia
```

`docs/owasp_zap_baseline.*` é o scan 1 (sem autenticação, só enxergou a superfície pública). Detalhes e correlação com OWASP: relatório final, §2.2–2.3.

## Gerar evidência da versão atual

```bash
uvicorn app.main:app --port 8000      # em outro terminal, com SEED_DEMO_DATA=true
bash scripts/gerar_evidencias.sh      # grava docs/evidencias/evidencias_<data>.txt
```
