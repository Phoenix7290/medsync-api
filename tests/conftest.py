import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel
from app.core.middleware import login_rate_limiter
from app.core.security import create_access_token
from app.database.session import engine, init_db
from app.main import app
from app.models.user import UserRole


@pytest.fixture(autouse=True)
def reset_db():
    login_rate_limiter.reset()
    SQLModel.metadata.drop_all(engine)
    init_db()
    yield
    login_rate_limiter.reset()
    SQLModel.metadata.drop_all(engine)
    init_db()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def receptionist_headers():
    token = create_access_token({
        "sub": "recepcao",
        "role": UserRole.RECEPTIONIST.value,
        "scopes": ["appointments:read", "appointments:write"],
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def doctor_roberto_headers():
    token = create_access_token({
        "sub": "dr_roberto",
        "role": UserRole.DOCTOR.value,
        "scopes": ["appointments:read", "appointments:write"],
        "doctor_crm": "CRM/SP 123456",
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def doctor_beatriz_headers():
    token = create_access_token({
        "sub": "dra_beatriz",
        "role": UserRole.DOCTOR.value,
        "scopes": ["appointments:read", "appointments:write"],
        "doctor_crm": "CRM/SP 654321",
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers():
    token = create_access_token({
        "sub": "admin",
        "role": UserRole.ADMIN.value,
        "scopes": ["admin:manage", "appointments:read", "appointments:write"],
        "mfa_verified": False,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_mfa_headers():
    token = create_access_token({
        "sub": "admin",
        "role": UserRole.ADMIN.value,
        "scopes": ["admin:manage", "appointments:read", "appointments:write"],
        "mfa_verified": True,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def partner_lab_headers():
    token = create_access_token({
        "sub": "partner-lab-01",
        "role": UserRole.PARTNER.value,
        "scopes": ["appointments:read_slots"],
    })
    return {"Authorization": f"Bearer {token}"}
