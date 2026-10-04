import os

# Ambiente de teste ISOLADO: precisa ser definido ANTES de importar a aplicação.
os.environ["SECRET_KEY"] = "test-only-secret-key-not-for-production-0123456789abcdef"
os.environ["DATABASE_URL"] = "sqlite:///./test_medsync.db"
os.environ["SEED_DEMO_DATA"] = "true"
os.environ["DEMO_USERS_PASSWORD"] = "Test-Password-123!"
os.environ["DEMO_LAB_CLIENT_SECRET"] = "Test-Lab-Secret-456!"
os.environ["DEMO_ADMIN_MFA_SECRET"] = "JBSWY3DPEHPK3PXP"

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

from app.core.middleware import login_rate_limiter, mfa_rate_limiter
from app.core.security import create_access_token, totp_code
from app.database.session import engine, init_db
from app.main import app
from app.models.user import UserRole

DEMO_PASSWORD = os.environ["DEMO_USERS_PASSWORD"]
LAB_SECRET = os.environ["DEMO_LAB_CLIENT_SECRET"]
ADMIN_MFA_SECRET = os.environ["DEMO_ADMIN_MFA_SECRET"]


def _reset():
    login_rate_limiter.reset()
    mfa_rate_limiter.reset()
    SQLModel.metadata.drop_all(engine)
    init_db()


@pytest.fixture(autouse=True)
def reset_db():
    _reset()
    yield


def pytest_sessionfinish(session, exitstatus):
    SQLModel.metadata.drop_all(engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def demo_password():
    return DEMO_PASSWORD


@pytest.fixture
def lab_secret():
    return LAB_SECRET


@pytest.fixture
def admin_mfa_code():
    return lambda: totp_code(ADMIN_MFA_SECRET)


def _headers(claims: dict) -> dict:
    return {"Authorization": f"Bearer {create_access_token(claims)}"}


@pytest.fixture
def receptionist_headers():
    return _headers({
        "sub": "recepcao", "role": UserRole.RECEPTIONIST.value,
        "scopes": ["appointments:read"],
    })


@pytest.fixture
def doctor_roberto_headers():
    return _headers({
        "sub": "dr_roberto", "role": UserRole.DOCTOR.value,
        "scopes": ["appointments:read", "appointments:write"],
        "doctor_crm": "CRM/SP 123456",
    })


@pytest.fixture
def doctor_beatriz_headers():
    return _headers({
        "sub": "dra_beatriz", "role": UserRole.DOCTOR.value,
        "scopes": ["appointments:read", "appointments:write"],
        "doctor_crm": "CRM/SP 654321",
    })


@pytest.fixture
def admin_headers():
    return _headers({
        "sub": "admin", "role": UserRole.ADMIN.value,
        "scopes": ["admin:manage", "appointments:read", "appointments:write"],
        "mfa_verified": False,
    })


@pytest.fixture
def admin_mfa_headers():
    return _headers({
        "sub": "admin", "role": UserRole.ADMIN.value,
        "scopes": ["admin:manage", "appointments:read", "appointments:write"],
        "mfa_verified": True,
    })


@pytest.fixture
def partner_lab_headers():
    return _headers({
        "sub": "partner-lab-01", "role": UserRole.PARTNER.value,
        "scopes": ["appointments:read_slots"],
    })
