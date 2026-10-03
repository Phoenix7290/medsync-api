from datetime import datetime, timezone
from typing import Generator
from sqlmodel import Session, SQLModel, create_engine, select
from app.core.config import settings
from app.models.appointment import Appointment

connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args=connect_args,
)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        statement = select(Appointment)
        existing = session.exec(statement).first()
        if not existing:
            app1 = Appointment(
                patient_name="Mariana Souza",
                patient_cpf="123.456.789-01",
                doctor_name="Dr. Roberto Silva",
                doctor_crm="CRM/SP 123456",
                appointment_datetime=datetime(2026, 10, 5, 9, 30, tzinfo=timezone.utc),
                specialty="Cardiologia",
                status="agendada",
                internal_audit_id="AUDIT-SEED-001",
                created_by_ip="10.0.0.1",
                internal_notes="Paciente com retorno prioritário",
            )
            app2 = Appointment(
                patient_name="Carlos Eduardo Lima",
                patient_cpf="987.654.321-09",
                doctor_name="Dra. Beatriz Santos",
                doctor_crm="CRM/SP 654321",
                appointment_datetime=datetime(2026, 10, 5, 11, 0, tzinfo=timezone.utc),
                specialty="Dermatologia",
                status="confirmada",
                internal_audit_id="AUDIT-SEED-002",
                created_by_ip="10.0.0.1",
                internal_notes="Consulta de rotina",
            )
            session.add(app1)
            session.add(app2)
            session.commit()


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
