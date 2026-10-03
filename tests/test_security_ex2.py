"""
Testes de Segurança para Controle de Exposição de Dados e Templates (Exercício 2).

Validações Obrigatórias:
1. Pydantic Response Models: comprovação de que campos internos de auditoria
   ('internal_audit_id', 'created_by_ip', 'internal_notes', 'created_at')
   NUNCA são expostos na resposta JSON aos clientes da API.
2. Jinja2 com herança de templates e sanitização contextual: comprovação de que
   injeções maliciosas de scripts (XSS Stored) são neutralizadas com escape automático.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import db_repository


@pytest.fixture(autouse=True)
def reset_database():
    """Garante isolamento dos testes restaurando o banco em memória antes de cada execução."""
    db_repository.reset()
    yield
    db_repository.reset()


client = TestClient(app)


def test_response_model_blocks_internal_audit_fields():
    """
    Exercício 2 (Controle de Exposição de Dados):
    Garante que os campos internos de auditoria presentes no objeto de banco
    NÃO vazam no JSON retornado pela API.
    """
    payload = {
        "patient_name": "Ana Clara Nogueira",
        "patient_cpf": "111.222.333-44",
        "doctor_name": "Dr. Lucas Martins",
        "doctor_crm": "CRM/SP 543210",
        "appointment_datetime": "2026-10-12T10:00:00Z",
        "specialty": "Clínica Geral",
        "status": "agendada",
    }

    response = client.post("/appointments/", json=payload)
    assert response.status_code == 201
    data = response.json()

    # Campos que DEVEM estar presentes (declarados no AppointmentResponse)
    assert "id" in data
    assert "patient_name" in data
    assert "doctor_name" in data
    assert "specialty" in data
    assert "status" in data

    # Decisão de Segurança: Campos de auditoria interna NUNCA podem vazar
    forbidden_audit_fields = [
        "internal_audit_id",
        "created_by_ip",
        "internal_notes",
        "created_at",
    ]
    for field in forbidden_audit_fields:
        assert field not in data, f"Vazamento de dado interno detectado! Campo '{field}' vazou no JSON."


def test_jinja2_template_autoescape_prevents_stored_xss():
    """
    Exercício 2 (Templates Seguros contra XSS):
    Simula a inserção de um payload malicioso no nome do paciente e valida
    que o Jinja2 aplica codificação automática de entidades HTML (autoescape),
    impedindo a execução de Cross-Site Scripting no navegador da recepção.
    """
    xss_payload = "<script>alert('VULNERABILIDADE_XSS')</script>"
    payload = {
        "patient_name": xss_payload,
        "patient_cpf": "000.111.222-33",
        "doctor_name": "Dr. Lucas Martins",
        "doctor_crm": "CRM/SP 543210",
        "appointment_datetime": "2026-10-12T11:00:00Z",
        "specialty": "Clínica Geral",
        "status": "agendada",
    }

    # Cadastra a consulta com payload malicioso via API
    create_response = client.post("/appointments/", json=payload)
    assert create_response.status_code == 201

    # Acessa a página HTML da recepção
    web_response = client.get("/recepcao/agenda")
    assert web_response.status_code == 200
    html_content = web_response.text

    # Decisão de Segurança: A tag executável bruta NÃO pode existir no HTML retornado
    assert "<script>alert('VULNERABILIDADE_XSS')</script>" not in html_content

    # O conteúdo deve estar devidamente escapado em entidades HTML seguras
    assert "&lt;script&gt;alert(&#39;VULNERABILIDADE_XSS&#39;)&lt;/script&gt;" in html_content or \
           "&lt;script&gt;alert('VULNERABILIDADE_XSS')&lt;/script&gt;" in html_content


def test_template_inheritance_renders_base_layout():
    """
    Exercício 2 (Herança de Templates):
    Valida que a página de agenda estende o base.html, garantindo consistência
    institucional e uniformidade dos elementos de segurança.
    """
    response = client.get("/recepcao/agenda")
    assert response.status_code == 200
    html = response.text

    # Verifica elementos definidos no base.html herdados pela agenda.html
    assert "MedSync • Rede de Clínicas Médicas" in html
    assert "Portal da Recepção" in html
    assert "LGPD (Art. 5º, II - Dados Sensíveis de Saúde)" in html
