from sqlmodel import Session

from app.core.security import verify_password
from app.database.session import engine
from app.database.users import UserRepository


def test_password_hashing_bcrypt(demo_password):
    with Session(engine) as session:
        admin = UserRepository(session).get_by_username("admin")
        assert admin is not None
        assert admin.hashed_password != demo_password
        assert admin.hashed_password.startswith("$2b$")
        assert verify_password(demo_password, admin.hashed_password) is True
        assert verify_password("WrongPassword", admin.hashed_password) is False


def test_login_success_and_jwt_generation(client, demo_password):
    response = client.post("/auth/token", data={"username": "recepcao", "password": demo_password})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "receptionist"
    assert data["scopes"] == ["appointments:read"]


def test_login_invalid_password(client):
    response = client.post("/auth/token", data={"username": "recepcao", "password": "SenhaIncorreta"})
    assert response.status_code == 401
    assert "incorretos" in response.json()["detail"].lower()


def test_login_unknown_user_same_error_as_wrong_password(client):
    response = client.post("/auth/token", data={"username": "nao_existe", "password": "qualquer-senha"})
    assert response.status_code == 401
    assert "incorretos" in response.json()["detail"].lower()


def test_non_admin_forbidden_on_admin_endpoint(client, receptionist_headers, doctor_roberto_headers):
    assert client.get("/admin/audit-logs", headers=receptionist_headers).status_code == 403
    assert client.get("/admin/audit-logs", headers=doctor_roberto_headers).status_code == 403


def test_admin_without_mfa_forbidden(client, admin_headers):
    response = client.get("/admin/audit-logs", headers=admin_headers)
    assert response.status_code == 403
    assert "MFA" in response.json()["detail"]


def test_admin_mfa_verification_flow(client, demo_password, admin_mfa_code):
    login = client.post("/auth/token", data={"username": "admin", "password": demo_password})
    assert login.status_code == 200
    assert login.json()["mfa_required"] is True
    first_factor = {"Authorization": f"Bearer {login.json()['access_token']}"}

    # Token do 1º fator ainda NÃO abre rota administrativa
    assert client.get("/admin/audit-logs", headers=first_factor).status_code == 403

    mfa_response = client.post("/auth/mfa/verify", json={"mfa_code": admin_mfa_code()}, headers=first_factor)
    assert mfa_response.status_code == 200
    elevated = {"Authorization": f"Bearer {mfa_response.json()['access_token']}"}

    audit = client.get("/admin/audit-logs", headers=elevated)
    assert audit.status_code == 200
    assert audit.json()["mfa_verified"] is True


def test_doctor_ownership_enforcement(client, doctor_roberto_headers):
    own = client.get("/appointments/1", headers=doctor_roberto_headers)
    assert own.status_code == 200
    assert own.json()["doctor_crm"] == "CRM/SP 123456"

    assert client.get("/appointments/2", headers=doctor_roberto_headers).status_code == 403
    assert client.delete("/appointments/2", headers=doctor_roberto_headers).status_code == 403
    assert client.delete("/appointments/1", headers=doctor_roberto_headers).status_code == 204


def test_m2m_token_exchange_success(client, lab_secret):
    response = client.post(
        "/auth/m2m/token",
        json={"client_id": "partner-lab-01", "client_secret": lab_secret, "grant_type": "client_credentials"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "partner"
    assert data["scopes"] == ["appointments:read_slots"]


def test_m2m_token_exchange_invalid_secret(client):
    response = client.post(
        "/auth/m2m/token",
        json={"client_id": "partner-lab-01", "client_secret": "ChaveInvalida", "grant_type": "client_credentials"},
    )
    assert response.status_code == 401


def test_partner_lab_accesses_allowed_endpoint(client, partner_lab_headers):
    response = client.get("/lab/available-slots", headers=partner_lab_headers)
    assert response.status_code == 200
    assert len(response.json()["available_slots"]) > 0


def test_partner_lab_forbidden_on_unauthorized_scope(client, partner_lab_headers):
    response = client.post("/lab/manage-patients", headers=partner_lab_headers)
    assert response.status_code == 403
    assert "insuficiente" in response.json()["detail"].lower()
