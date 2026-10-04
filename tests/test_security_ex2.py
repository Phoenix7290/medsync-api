from datetime import datetime, timezone
from sqlmodel import Session
from app.database.session import engine
from app.models.appointment import Appointment


def test_response_model_blocks_internal_audit_fields(client, doctor_roberto_headers):
    payload = {
        "patient_name": "Ana Clara Nogueira",
        "patient_cpf": "111.222.333-44",
        "doctor_name": "Dr. Roberto Silva",
        "doctor_crm": "CRM/SP 123456",
        "appointment_datetime": "2026-10-12T10:00:00Z",
        "specialty": "Clínica Geral",
        "status": "agendada",
    }

    response = client.post("/appointments/", json=payload, headers=doctor_roberto_headers)
    assert response.status_code == 201
    data = response.json()

    assert "id" in data
    assert "patient_name" in data
    assert "doctor_name" in data
    assert "specialty" in data
    assert "status" in data

    forbidden_audit_fields = [
        "internal_audit_id",
        "created_by_ip",
        "internal_notes",
        "created_at",
    ]
    for field in forbidden_audit_fields:
        assert field not in data


def test_jinja2_template_autoescape_prevents_stored_xss(client, receptionist_headers):
    with Session(engine) as session:
        xss_app = Appointment(
            patient_name="<script>alert('VULNERABILIDADE_XSS')</script>",
            patient_cpf="000.111.222-33",
            doctor_name="Dr. Lucas Martins",
            doctor_crm="CRM/SP 543210",
            appointment_datetime=datetime(2026, 10, 12, 11, 0, tzinfo=timezone.utc),
            specialty="Clínica Geral",
            status="agendada",
        )
        session.add(xss_app)
        session.commit()

    web_response = client.get("/recepcao/agenda", headers=receptionist_headers)
    assert web_response.status_code == 200
    html_content = web_response.text

    assert "<script>alert('VULNERABILIDADE_XSS')</script>" not in html_content
    assert "&lt;script&gt;alert(&#39;VULNERABILIDADE_XSS&#39;)&lt;/script&gt;" in html_content or \
           "&lt;script&gt;alert('VULNERABILIDADE_XSS')&lt;/script&gt;" in html_content


def test_template_inheritance_renders_base_layout(client, receptionist_headers):
    response = client.get("/recepcao/agenda", headers=receptionist_headers)
    assert response.status_code == 200
    html = response.text

    assert "MedSync • Rede de Clínicas Médicas" in html
    assert "Portal da Recepção" in html
    assert "LGPD (Dados Sensíveis de Saúde)" in html
