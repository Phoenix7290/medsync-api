import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from app.models.appointment import AppointmentCreate, AppointmentInternal


class AppointmentMemoryRepository:
    def __init__(self) -> None:
        self._storage: Dict[int, AppointmentInternal] = {}
        self._next_id: int = 1
        self._seed_initial_data()

    def _seed_initial_data(self) -> None:
        initial_records = [
            AppointmentCreate(
                patient_name="Mariana Souza",
                patient_cpf="123.456.789-01",
                doctor_name="Dr. Roberto Silva",
                doctor_crm="CRM/SP 123456",
                appointment_datetime=datetime(2026, 10, 5, 9, 30, tzinfo=timezone.utc),
                specialty="Cardiologia",
                status="agendada",
            ),
            AppointmentCreate(
                patient_name="Carlos Eduardo Lima",
                patient_cpf="987.654.321-09",
                doctor_name="Dra. Beatriz Santos",
                doctor_crm="CRM/SP 654321",
                appointment_datetime=datetime(2026, 10, 5, 11, 0, tzinfo=timezone.utc),
                specialty="Dermatologia",
                status="confirmada",
            ),
        ]
        for item in initial_records:
            self.create(item, client_ip="10.0.0.1", internal_notes="Paciente com retorno prioritário")

    def create(
        self,
        data: AppointmentCreate,
        client_ip: str = "127.0.0.1",
        internal_notes: Optional[str] = None
    ) -> AppointmentInternal:
        appointment_id = self._next_id
        self._next_id += 1

        record = AppointmentInternal(
            id=appointment_id,
            patient_name=data.patient_name,
            patient_cpf=data.patient_cpf,
            doctor_name=data.doctor_name,
            doctor_crm=data.doctor_crm,
            appointment_datetime=data.appointment_datetime,
            specialty=data.specialty,
            status=data.status,
            internal_audit_id=f"AUDIT-{uuid.uuid4().hex[:12].upper()}",
            created_by_ip=client_ip,
            internal_notes=internal_notes or "Criado via API de agendamento",
            created_at=datetime.now(timezone.utc),
        )
        self._storage[appointment_id] = record
        return record

    def get_by_id(self, appointment_id: int) -> Optional[AppointmentInternal]:
        return self._storage.get(appointment_id)

    def list_all(self) -> List[AppointmentInternal]:
        return list(self._storage.values())

    def delete(self, appointment_id: int) -> bool:
        if appointment_id in self._storage:
            del self._storage[appointment_id]
            return True
        return False

    def reset(self) -> None:
        self._storage.clear()
        self._next_id = 1
        self._seed_initial_data()


db_repository = AppointmentMemoryRepository()


def get_db_repository() -> AppointmentMemoryRepository:
    return db_repository
