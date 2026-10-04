from datetime import datetime, timezone
from typing import Generator

from sqlmodel import Session, SQLModel, create_engine, select

from app.core.config import settings
from app.core.security import generate_mfa_secret, hash_password
from app.models.appointment import Appointment
from app.models.user import PartnerClient, User, UserRole

connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args=connect_args,
)


def _seed_demo_users(session: Session) -> None:
    """Cria usuários de demonstração SOMENTE se SEED_DEMO_DATA=true e a senha vier do ambiente."""
    password = settings.DEMO_USERS_PASSWORD
    if not password or session.exec(select(User)).first():
        return

    admin_mfa_secret = settings.DEMO_ADMIN_MFA_SECRET or generate_mfa_secret()
    if not settings.DEMO_ADMIN_MFA_SECRET:
        print(f"[DEV ONLY] Segredo MFA do admin de demonstração (cadastre no autenticador): {admin_mfa_secret}")

    hashed = hash_password(password)
    session.add_all([
        User(username="admin", email="admin@medsync.com", full_name="Administrador Geral",
             role=UserRole.ADMIN, hashed_password=hashed, mfa_enabled=True, mfa_secret=admin_mfa_secret),
        User(username="dr_roberto", email="roberto@medsync.com", full_name="Dr. Roberto Silva",
             role=UserRole.DOCTOR, hashed_password=hashed, doctor_crm="CRM/SP 123456"),
        User(username="dra_beatriz", email="beatriz@medsync.com", full_name="Dra. Beatriz Santos",
             role=UserRole.DOCTOR, hashed_password=hashed, doctor_crm="CRM/SP 654321"),
        User(username="recepcao", email="recepcao@medsync.com", full_name="Operador da Recepção",
             role=UserRole.RECEPTIONIST, hashed_password=hashed),
    ])
    if settings.DEMO_LAB_CLIENT_SECRET:
        session.add(PartnerClient(
            client_id="partner-lab-01",
            client_secret_hash=hash_password(settings.DEMO_LAB_CLIENT_SECRET),
            allowed_scopes="appointments:read_slots",
        ))
    session.commit()


def _seed_demo_appointments(session: Session) -> None:
    if session.exec(select(Appointment)).first():
        return
    session.add_all([
        Appointment(
            patient_name="Mariana Souza", patient_cpf="123.456.789-01",
            doctor_name="Dr. Roberto Silva", doctor_crm="CRM/SP 123456",
            appointment_datetime=datetime(2026, 10, 5, 9, 30, tzinfo=timezone.utc),
            specialty="Cardiologia", status="agendada",
            internal_audit_id="AUDIT-SEED-001", created_by_ip="10.0.0.1",
            internal_notes="Paciente com retorno prioritário",
        ),
        Appointment(
            patient_name="Carlos Eduardo Lima", patient_cpf="987.654.321-09",
            doctor_name="Dra. Beatriz Santos", doctor_crm="CRM/SP 654321",
            appointment_datetime=datetime(2026, 10, 5, 11, 0, tzinfo=timezone.utc),
            specialty="Dermatologia", status="confirmada",
            internal_audit_id="AUDIT-SEED-002", created_by_ip="10.0.0.1",
            internal_notes="Consulta de rotina",
        ),
    ])
    session.commit()


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    if settings.SEED_DEMO_DATA:
        with Session(engine) as session:
            _seed_demo_users(session)
            _seed_demo_appointments(session)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
