import pytest
from app.core.security import verify_password
from app.database.users import user_repository


def test_password_hashing_bcrypt():
    admin = user_repository.get_by_username("admin")
    assert admin is not None
    assert admin.hashed_password != "Admin@123"
    assert admin.hashed_password.startswith("$2b$")
    assert verify_password("Admin@123", admin.hashed_password) is True
    assert verify_password("WrongPassword", admin.hashed_password) is False


def test_login_success_and_jwt_generation(client):
    response = client.post(
        "/auth/token",
        data={"username": "recepcao", "password": "Recepcao@123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "receptionist"


def test_login_invalid_password(client):
    response = client.post(
        "/auth/token",
        data={"username": "recepcao", "password": "SenhaIncorreta"},
    )
    assert response.status_code == 401
    assert "incorrect" in response.json()["detail"].lower() or "incorretos" in response.json()["detail"].lower()


def test_non_admin_forbidden_on_admin_endpoint(client, receptionist_headers, doctor_roberto_headers):
    response_rec = client.get("/admin/audit-logs", headers=receptionist_headers)
    assert response_rec.status_code == 403

    response_doc = client.get("/admin/audit-logs", headers=doctor_roberto_headers)
    assert response_doc.status_code == 403


def test_admin_without_mfa_forbidden(client, admin_headers):
    response = client.get("/admin/audit-logs", headers=admin_headers)
    assert response.status_code == 403
    assert "MFA" in response.json()["detail"]


def test_admin_mfa_verification_flow(client):
    mfa_response = client.post(
        "/auth/mfa/verify",
        json={"username": "admin", "mfa_code": "849201"},
    )
    assert mfa_response.status_code == 200
    elevated_token = mfa_response.json()["access_token"]

    admin_audit_response = client.get(
        "/admin/audit-logs",
        headers={"Authorization": f"Bearer {elevated_token}"},
    )
    assert admin_audit_response.status_code == 200
    data = admin_audit_response.json()
    assert data["status"] == "success"
    assert data["mfa_verified"] is True


def test_doctor_ownership_enforcement(client, doctor_roberto_headers, doctor_beatriz_headers):
    response_own = client.get("/appointments/1", headers=doctor_roberto_headers)
    assert response_own.status_code == 200
    assert response_own.json()["doctor_crm"] == "CRM/SP 123456"

    response_other = client.get("/appointments/2", headers=doctor_roberto_headers)
    assert response_other.status_code == 403

    response_delete_forbidden = client.delete("/appointments/2", headers=doctor_roberto_headers)
    assert response_delete_forbidden.status_code == 403

    response_delete_own = client.delete("/appointments/1", headers=doctor_roberto_headers)
    assert response_delete_own.status_code == 204


def test_m2m_token_exchange_success(client):
    response = client.post(
        "/auth/m2m/token",
        json={
            "client_id": "partner-lab-01",
            "client_secret": "LabSecretKey2026!",
            "grant_type": "client_credentials",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["role"] == "partner"
    assert "appointments:read_slots" in data["scopes"]


def test_m2m_token_exchange_invalid_secret(client):
    response = client.post(
        "/auth/m2m/token",
        json={
            "client_id": "partner-lab-01",
            "client_secret": "ChaveInvalida",
            "grant_type": "client_credentials",
        },
    )
    assert response.status_code == 401


def test_partner_lab_accesses_allowed_endpoint(client, partner_lab_headers):
    response = client.get("/lab/available-slots", headers=partner_lab_headers)
    assert response.status_code == 200
    data = response.json()
    assert "available_slots" in data
    assert len(data["available_slots"]) > 0


def test_partner_lab_forbidden_on_unauthorized_scope(client, partner_lab_headers):
    response = client.post("/lab/manage-patients", headers=partner_lab_headers)
    assert response.status_code == 403
    assert "insuficiente" in response.json()["detail"].lower()
