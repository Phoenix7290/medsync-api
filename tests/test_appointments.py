def test_root_healthcheck(client):
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "online"
    assert payload["service"] == "MedSync API"


def test_create_appointment_success(client, doctor_roberto_headers):
    new_appointment_payload = {
        "patient_name": "Juliana Mendes",
        "patient_cpf": "333.444.555-66",
        "doctor_name": "Dr. Roberto Silva",
        "doctor_crm": "CRM/SP 123456",
        "appointment_datetime": "2026-10-10T14:30:00Z",
        "specialty": "Ortopedia",
        "status": "agendada",
    }

    response = client.post("/appointments/", json=new_appointment_payload, headers=doctor_roberto_headers)

    assert response.status_code == 201
    data = response.json()
    assert data["id"] is not None
    assert data["patient_name"] == "Juliana Mendes"
    assert data["doctor_name"] == "Dr. Roberto Silva"
    assert data["specialty"] == "Ortopedia"
    assert data["status"] == "agendada"


def test_list_appointments(client, receptionist_headers):
    response = client.get("/appointments/", headers=receptionist_headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 2


def test_get_appointment_by_id(client, receptionist_headers):
    response = client.get("/appointments/1", headers=receptionist_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 1
    assert "patient_name" in data


def test_get_appointment_not_found(client, receptionist_headers):
    response = client.get("/appointments/99999", headers=receptionist_headers)
    assert response.status_code == 404
    assert "não encontrada" in response.json()["detail"]


def test_delete_appointment(client, doctor_roberto_headers, receptionist_headers):
    response = client.delete("/appointments/1", headers=doctor_roberto_headers)
    assert response.status_code == 204

    check_response = client.get("/appointments/1", headers=receptionist_headers)
    assert check_response.status_code == 404
