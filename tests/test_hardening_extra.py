import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_zap_corp_header_present(client):
    assert client.get("/").headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert client.get("/openapi.json").headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_no_store_cache_control_on_all_responses(client, doctor_roberto_headers):
    assert client.get("/").headers["Cache-Control"] == "no-store"
    assert client.get("/openapi.json").headers["Cache-Control"] == "no-store"
    # também em respostas com dados de saúde e em respostas de erro
    assert client.get("/appointments/", headers=doctor_roberto_headers).headers["Cache-Control"] == "no-store"
    assert client.get("/appointments/").headers["Cache-Control"] == "no-store"


def test_agenda_filters_by_day_and_paginates(client, receptionist_headers):
    # seed: 2 consultas em 2026-10-05
    same_day = client.get("/recepcao/agenda?data=2026-10-05", headers=receptionist_headers)
    assert same_day.status_code == 200
    assert "Mariana Souza" in same_day.text and "Carlos Eduardo Lima" in same_day.text
    assert "05/10/2026" in same_day.text

    other_day = client.get("/recepcao/agenda?data=2026-10-06", headers=receptionist_headers)
    assert other_day.status_code == 200
    assert "Mariana Souza" not in other_day.text
    assert "Nenhuma consulta encontrada" in other_day.text

    first_page = client.get("/recepcao/agenda?limit=1", headers=receptionist_headers).text
    assert ("Mariana Souza" in first_page) != ("Carlos Eduardo Lima" in first_page)  # só uma linha


def test_agenda_rejects_invalid_query(client, receptionist_headers):
    for query in ("data=abc", "data=2026-13-45", "limit=0", "limit=100000", "offset=-1"):
        assert client.get(f"/recepcao/agenda?{query}", headers=receptionist_headers).status_code == 422


def test_forbidden_message_does_not_list_allowed_roles(client, receptionist_headers):
    detail = client.delete("/appointments/1", headers=receptionist_headers).json()["detail"]
    assert "doctor" not in detail and "admin" not in detail and "[" not in detail


def test_docs_disabled_in_production():
    env = {
        **os.environ,
        "ENVIRONMENT": "production",
        "SECRET_KEY": "prod-like-secret-key-for-this-subprocess-0123456789abcdef",
        "DATABASE_URL": "sqlite:///:memory:",
        "SEED_DEMO_DATA": "false",
    }
    code = (
        "from app.main import app;"
        "print(app.docs_url, app.redoc_url, app.openapi_url)"
    )
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "None None None"
