from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import jwt
from app.core.config import settings
from app.core.dependencies import get_current_token_payload
from app.core.security import create_access_token
from app.database.session import get_session
from app.main import app
from app.models.appointment import AppointmentCreate


def test_expired_token_rejected_with_401(client):
    past_time = datetime.now(timezone.utc) - timedelta(hours=2)
    expired_token = jwt.encode(
        {"sub": "dr_roberto", "role": "doctor", "exp": past_time, "iat": past_time - timedelta(hours=1)},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    response = client.get("/appointments/", headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    assert "inválidas ou token expirado" in response.json()["detail"]


def test_invalid_signature_token_rejected_with_401(client):
    fake_secret = "attacker-unauthorized-fake-secret-key-32b"
    forged_token = jwt.encode(
        {"sub": "admin", "role": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        fake_secret,
        algorithm=settings.ALGORITHM,
    )
    response = client.get("/admin/audit-logs", headers={"Authorization": f"Bearer {forged_token}"})
    assert response.status_code == 401


def test_cross_doctor_appointment_creation_spoofing(client, doctor_roberto_headers):
    spoofed_payload = {
        "patient_name": "Paciente da Dra Beatriz",
        "patient_cpf": "555.666.777-88",
        "doctor_name": "Dra. Beatriz Santos",
        "doctor_crm": "CRM/SP 654321",
        "appointment_datetime": "2026-10-20T10:00:00Z",
        "specialty": "Dermatologia",
        "status": "agendada",
    }
    response = client.post("/appointments/", json=spoofed_payload, headers=doctor_roberto_headers)
    assert response.status_code == 403
    assert "próprio CRM" in response.json()["detail"]


def test_unit_with_mocked_database_session(client, doctor_roberto_headers):
    mock_session = MagicMock()
    mock_session.exec.return_value.all.return_value = []

    app.dependency_overrides[get_session] = lambda: mock_session

    try:
        response = client.get("/appointments/", headers=doctor_roberto_headers)
        assert response.status_code == 200
        assert response.json() == []
        mock_session.exec.assert_called_once()
    finally:
        app.dependency_overrides.clear()


def test_openapi_specification_audit(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()

    assert "openapi" in schema
    assert "paths" in schema
    paths = schema["paths"]

    assert "/appointments/" in paths
    assert "/admin/audit-logs" in paths
    assert "/lab/available-slots" in paths

    admin_get = paths["admin/audit-logs"]["get"] if "admin/audit-logs" in paths else paths["/admin/audit-logs"]["get"]
    assert "security" in admin_get

    components = schema.get("components", {})
    schemas = components.get("schemas", {})
    assert "AppointmentResponse" in schemas

    response_properties = schemas["AppointmentResponse"]["properties"]
    forbidden_internal_fields = ["internal_audit_id", "created_by_ip", "internal_notes", "created_at"]
    for field in forbidden_internal_fields:
        assert field not in response_properties
