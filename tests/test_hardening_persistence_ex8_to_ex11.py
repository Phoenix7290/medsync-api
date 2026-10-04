from sqlmodel import Session, select
from app.database.session import engine
from app.models.appointment import Appointment


def test_extra_forbid_blocks_parameter_pollution(client, doctor_roberto_headers):
    payload = {
        "patient_name": "Marcos Silva",
        "patient_cpf": "123.456.789-01",
        "doctor_name": "Dr. Roberto Silva",
        "doctor_crm": "CRM/SP 123456",
        "appointment_datetime": "2026-10-15T10:00:00Z",
        "specialty": "Cardiologia",
        "status": "agendada",
        "unauthorized_field": "injected_value",
    }
    response = client.post("/appointments/", json=payload, headers=doctor_roberto_headers)
    assert response.status_code == 422
    assert "extra_forbidden" in str(response.json())


def test_whitelist_and_regex_validation(client, doctor_roberto_headers):
    payload_invalid_cpf = {
        "patient_name": "Marcos Silva",
        "patient_cpf": "123.456.789-XX",
        "doctor_name": "Dr. Roberto Silva",
        "doctor_crm": "CRM/SP 123456",
        "appointment_datetime": "2026-10-15T10:00:00Z",
        "specialty": "Cardiologia",
        "status": "agendada",
    }
    resp_cpf = client.post("/appointments/", json=payload_invalid_cpf, headers=doctor_roberto_headers)
    assert resp_cpf.status_code == 422
    assert "patient_cpf" in str(resp_cpf.json())

    payload_invalid_crm = {
        "patient_name": "Marcos Silva",
        "patient_cpf": "123.456.789-01",
        "doctor_name": "Dr. Roberto Silva",
        "doctor_crm": "INVALID_CRM",
        "appointment_datetime": "2026-10-15T10:00:00Z",
        "specialty": "Cardiologia",
        "status": "agendada",
    }
    resp_crm = client.post("/appointments/", json=payload_invalid_crm, headers=doctor_roberto_headers)
    assert resp_crm.status_code == 422
    assert "doctor_crm" in str(resp_crm.json())

    payload_xss_name = {
        "patient_name": "<script>alert('xss')</script>",
        "patient_cpf": "123.456.789-01",
        "doctor_name": "Dr. Roberto Silva",
        "doctor_crm": "CRM/SP 123456",
        "appointment_datetime": "2026-10-15T10:00:00Z",
        "specialty": "Cardiologia",
        "status": "agendada",
    }
    resp_xss = client.post("/appointments/", json=payload_xss_name, headers=doctor_roberto_headers)
    assert resp_xss.status_code == 422
    assert "patient_name" in str(resp_xss.json())


def test_security_headers_present(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_cors_explicit_allowlist(client):
    response_allowed = client.options(
        "/appointments/",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response_allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"

    response_denied = client.options(
        "/appointments/",
        headers={
            "Origin": "https://attacker-origin.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response_denied.headers.get("access-control-allow-origin") != "https://attacker-origin.com"


def test_login_rate_limiting(client):
    login_data = {"username": "recepcao", "password": "WrongPassword"}
    for _ in range(5):
        client.post("/auth/token", data=login_data)

    rate_limited_response = client.post("/auth/token", data=login_data)
    assert rate_limited_response.status_code == 429
    assert "Muitas tentativas" in rate_limited_response.json()["detail"]
    assert rate_limited_response.headers.get("Retry-After") == "60"


def test_sqlmodel_persistence_and_parameterized_query(client, doctor_roberto_headers):
    payload = {
        "patient_name": "Daniela Paiva",
        "patient_cpf": "444.555.666-77",
        "doctor_name": "Dr. Roberto Silva",
        "doctor_crm": "CRM/SP 123456",
        "appointment_datetime": "2026-10-18T16:00:00Z",
        "specialty": "Cardiologia",
        "status": "agendada",
    }
    response = client.post("/appointments/", json=payload, headers=doctor_roberto_headers)
    assert response.status_code == 201
    created_id = response.json()["id"]

    with Session(engine) as session:
        statement = select(Appointment).where(Appointment.id == created_id)
        db_record = session.exec(statement).first()
        assert db_record is not None
        assert db_record.patient_name == "Daniela Paiva"
        assert db_record.internal_audit_id.startswith("AUDIT-")
        assert db_record.created_at is not None
