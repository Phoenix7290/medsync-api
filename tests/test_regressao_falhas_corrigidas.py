"""Testes de regressão: cada teste reproduz um ataque real que EXISTIA antes da correção.

Rastreabilidade (threat model do Ex. 4 -> teste):
  - Elevation of Privilege via /auth/register ............ test_register_*
  - Elevation of Privilege via MFA fixo/sem 1º fator ..... test_mfa_*
  - Elevation of Privilege via token M2M em rotas humanas  test_partner_token_*
  - Broken Authentication na página da recepção .......... test_agenda_*
  - Broken Function Level Authorization (recepção apaga) . test_receptionist_*
"""
from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import settings

NEW_USER = {
    "username": "novo_usuario",
    "email": "novo@medsync.com",
    "full_name": "Novo Usuario",
    "role": "receptionist",
    "password": "SenhaForte-123",
}

APPOINTMENT = {
    "patient_name": "Paciente Teste",
    "patient_cpf": "111.222.333-44",
    "doctor_name": "Dr. Roberto Silva",
    "doctor_crm": "CRM/SP 123456",
    "appointment_datetime": "2026-10-20T10:00:00Z",
    "specialty": "Cardiologia",
    "status": "agendada",
}


# --- /auth/register ---------------------------------------------------------
def test_register_requires_authentication(client):
    assert client.post("/auth/register", json=NEW_USER).status_code == 401


def test_register_self_service_admin_escalation_blocked(client):
    payload = {**NEW_USER, "role": "admin"}
    assert client.post("/auth/register", json=payload).status_code == 401


def test_register_forbidden_for_non_admin_and_admin_without_mfa(client, doctor_roberto_headers, admin_headers):
    assert client.post("/auth/register", json=NEW_USER, headers=doctor_roberto_headers).status_code == 403
    assert client.post("/auth/register", json=NEW_USER, headers=admin_headers).status_code == 403


def test_register_by_admin_with_mfa_succeeds_and_password_is_hashed(client, admin_mfa_headers):
    response = client.post("/auth/register", json=NEW_USER, headers=admin_mfa_headers)
    assert response.status_code == 201
    body = response.json()
    assert "password" not in body and "hashed_password" not in body
    assert body["mfa_provisioning_secret"] is None  # só admins recebem segredo MFA


def test_register_rejects_partner_role_unknown_fields_and_weak_input(client, admin_mfa_headers):
    assert client.post("/auth/register", json={**NEW_USER, "role": "partner"}, headers=admin_mfa_headers).status_code == 422
    assert client.post("/auth/register", json={**NEW_USER, "is_superuser": True}, headers=admin_mfa_headers).status_code == 422
    assert client.post("/auth/register", json={**NEW_USER, "password": "123"}, headers=admin_mfa_headers).status_code == 422
    assert client.post("/auth/register", json={**NEW_USER, "username": "x<script>"}, headers=admin_mfa_headers).status_code == 422
    # médico sem CRM válido
    assert client.post("/auth/register", json={**NEW_USER, "role": "doctor"}, headers=admin_mfa_headers).status_code == 422


def test_register_duplicate_username_rejected(client, admin_mfa_headers):
    assert client.post("/auth/register", json=NEW_USER, headers=admin_mfa_headers).status_code == 201
    assert client.post("/auth/register", json=NEW_USER, headers=admin_mfa_headers).status_code == 400


# --- MFA --------------------------------------------------------------------
def test_mfa_requires_first_factor_token(client, admin_mfa_code):
    # Antes: bastava {"username": "admin", "mfa_code": "849201"} para obter token admin.
    assert client.post("/auth/mfa/verify", json={"mfa_code": admin_mfa_code()}).status_code == 401


def test_mfa_old_static_code_rejected(client, demo_password):
    login = client.post("/auth/token", data={"username": "admin", "password": demo_password}).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    assert client.post("/auth/mfa/verify", json={"mfa_code": "849201"}, headers=headers).status_code == 401


def test_mfa_rejected_for_account_without_mfa(client, demo_password):
    login = client.post("/auth/token", data={"username": "dr_roberto", "password": demo_password}).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    assert client.post("/auth/mfa/verify", json={"mfa_code": "123456"}, headers=headers).status_code == 400


def test_mfa_brute_force_is_rate_limited(client, demo_password):
    login = client.post("/auth/token", data={"username": "admin", "password": demo_password}).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    statuses = [
        client.post("/auth/mfa/verify", json={"mfa_code": f"{i:06d}"}, headers=headers).status_code
        for i in range(8)
    ]
    assert statuses[:5] == [401] * 5
    assert 429 in statuses[5:]


# --- Token M2M (laboratório) em rotas de pacientes ---------------------------
def test_partner_token_cannot_touch_appointments(client, partner_lab_headers):
    assert client.get("/appointments/", headers=partner_lab_headers).status_code == 403
    assert client.get("/appointments/1", headers=partner_lab_headers).status_code == 403
    assert client.post("/appointments/", json=APPOINTMENT, headers=partner_lab_headers).status_code == 403
    assert client.delete("/appointments/1", headers=partner_lab_headers).status_code == 403


def test_partner_token_cannot_open_agenda_or_admin(client, partner_lab_headers):
    assert client.get("/recepcao/agenda", headers=partner_lab_headers).status_code == 403
    assert client.get("/admin/audit-logs", headers=partner_lab_headers).status_code == 403


def test_human_token_cannot_use_lab_slots_scope(client, doctor_roberto_headers):
    assert client.get("/lab/available-slots", headers=doctor_roberto_headers).status_code == 403


# --- Página da recepção -----------------------------------------------------
def test_agenda_requires_authentication(client):
    assert client.get("/recepcao/agenda").status_code == 401


def test_agenda_forbidden_for_doctor_allowed_for_reception_and_admin(client, doctor_roberto_headers, receptionist_headers, admin_headers):
    assert client.get("/recepcao/agenda", headers=doctor_roberto_headers).status_code == 403
    assert client.get("/recepcao/agenda", headers=receptionist_headers).status_code == 200
    assert client.get("/recepcao/agenda", headers=admin_headers).status_code == 200


def test_agenda_csp_allows_inline_style_but_not_scripts(client, receptionist_headers):
    csp = client.get("/recepcao/agenda", headers=receptionist_headers).headers["Content-Security-Policy"]
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "script-src" not in csp and "default-src 'self'" in csp


# --- Papéis nas rotas de consultas ------------------------------------------
def test_receptionist_cannot_create_or_delete_but_can_read(client, receptionist_headers):
    assert client.post("/appointments/", json=APPOINTMENT, headers=receptionist_headers).status_code == 403
    assert client.delete("/appointments/1", headers=receptionist_headers).status_code == 403
    assert client.get("/appointments/1", headers=receptionist_headers).status_code == 200


def test_doctor_list_is_filtered_to_own_crm(client, doctor_roberto_headers):
    data = client.get("/appointments/", headers=doctor_roberto_headers).json()
    assert len(data) == 1 and data[0]["doctor_crm"] == "CRM/SP 123456"


def test_doctor_token_without_crm_claim_sees_nothing(client):
    from app.core.security import create_access_token
    token = create_access_token({"sub": "dr_x", "role": "doctor", "scopes": ["appointments:read", "appointments:write"]})
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/appointments/", headers=headers).json() == []
    assert client.get("/appointments/1", headers=headers).status_code == 403
    assert client.delete("/appointments/1", headers=headers).status_code == 403
    assert client.post("/appointments/", json=APPOINTMENT, headers=headers).status_code == 403


def test_status_and_text_fields_use_whitelist(client, doctor_roberto_headers):
    assert client.post("/appointments/", json={**APPOINTMENT, "status": "<img src=x onerror=alert(1)>"}, headers=doctor_roberto_headers).status_code == 422
    assert client.post("/appointments/", json={**APPOINTMENT, "specialty": "<script>x</script>"}, headers=doctor_roberto_headers).status_code == 422
    assert client.post("/appointments/", json={**APPOINTMENT, "doctor_name": "Robert'); DROP TABLE users;--"}, headers=doctor_roberto_headers).status_code == 422


# --- JWT --------------------------------------------------------------------
def test_token_without_exp_is_rejected(client):
    token = jwt.encode({"sub": "dr_roberto", "role": "doctor", "scopes": ["appointments:read"]}, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    assert client.get("/appointments/", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_alg_none_token_is_rejected(client):
    token = jwt.encode(
        {"sub": "admin", "role": "admin", "mfa_verified": True, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        key="", algorithm="none",
    )
    assert client.get("/admin/audit-logs", headers={"Authorization": f"Bearer {token}"}).status_code == 401


# --- Segredos ---------------------------------------------------------------
def test_no_hardcoded_secret_defaults_in_source():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "app"
    source = "\n".join(p.read_text(encoding="utf-8") for p in root.rglob("*.py"))
    for forbidden in ("849201", "Admin@123", "Doctor@123", "Recepcao@123", "LabSecretKey2026!", "09d25e094faa6ca2"):
        assert forbidden not in source
