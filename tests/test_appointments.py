"""
Testes automatizados da API de Agendamento de Consultas (Exercício 1).

Cobre o fluxo de inicialização da aplicação FastAPI e o caminho de sucesso
do endpoint RESTful de criação e consulta de agendamentos.
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


def test_root_healthcheck():
    """Valida que o serviço inicializa corretamente e expõe endpoint de healthcheck."""
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "online"
    assert payload["service"] == "MedSync API"


def test_create_appointment_success():
    """
    Exercício 1: Valida o caminho de sucesso da criação de uma consulta médica
    via APIRouter e FastAPI.
    """
    new_appointment_payload = {
        "patient_name": "Juliana Mendes",
        "patient_cpf": "333.444.555-66",
        "doctor_name": "Dr. Fernando Costa",
        "doctor_crm": "CRM/SP 987654",
        "appointment_datetime": "2026-10-10T14:30:00Z",
        "specialty": "Ortopedia",
        "status": "agendada",
    }

    response = client.post("/appointments/", json=new_appointment_payload)

    # Asserções de conformidade HTTP RESTful
    assert response.status_code == 201
    data = response.json()
    assert data["id"] is not None
    assert data["patient_name"] == "Juliana Mendes"
    assert data["doctor_name"] == "Dr. Fernando Costa"
    assert data["specialty"] == "Ortopedia"
    assert data["status"] == "agendada"


def test_list_appointments():
    """Valida a listagem das consultas existentes."""
    response = client.get("/appointments/")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 2  # Registros iniciais semeados


def test_get_appointment_by_id():
    """Valida a recuperação de uma consulta específica pelo ID."""
    response = client.get("/appointments/1")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 1
    assert "patient_name" in data


def test_get_appointment_not_found():
    """Valida o tratamento de erro 404 ao buscar consulta inexistente."""
    response = client.get("/appointments/99999")
    assert response.status_code == 404
    assert "não encontrada" in response.json()["detail"]


def test_delete_appointment():
    """Valida o cancelamento/remoção de consulta."""
    response = client.delete("/appointments/1")
    assert response.status_code == 204

    # Verifica que a consulta não existe mais
    check_response = client.get("/appointments/1")
    assert check_response.status_code == 404
