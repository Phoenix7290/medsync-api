"""
Módulo de Banco de Dados em Memória (Fase Inicial - Exercício 1).

Decisões de Arquitetura e Segurança:
1. Conforme planejado para o ciclo de desenvolvimento seguro da disciplina,
   a aplicação inicia com uma camada de persistência em memória padronizada
   para validar regras e fluxos de negócio, preparando o terreno para a migração
   segura para SQLModel parametrizado no Exercício 11.
2. Cada registro gerado recebe metadados de auditoria gerados internamente
   pelo servidor (como internal_audit_id UUID, timestamp de criação e IP),
   garantindo que clientes externos não consigam forjar metadados.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from app.models.appointment import AppointmentCreate, AppointmentInternal


class AppointmentMemoryRepository:
    """Repositório em memória para persistência segura de consultas."""

    def __init__(self) -> None:
        self._storage: Dict[int, AppointmentInternal] = {}
        self._next_id: int = 1
        self._seed_initial_data()

    def _seed_initial_data(self) -> None:
        """Semeia dados iniciais para viabilizar testes e visualização na recepção."""
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
        """Cria e armazena uma consulta com campos de auditoria controlados pelo servidor."""
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
        """Recupera uma consulta pelo identificador."""
        return self._storage.get(appointment_id)

    def list_all(self) -> List[AppointmentInternal]:
        """Lista todas as consultas cadastradas."""
        return list(self._storage.values())

    def delete(self, appointment_id: int) -> bool:
        """Remove uma consulta existente."""
        if appointment_id in self._storage:
            del self._storage[appointment_id]
            return True
        return False

    def reset(self) -> None:
        """Limpa e restaura o estado inicial para baterias de testes."""
        self._storage.clear()
        self._next_id = 1
        self._seed_initial_data()


# Instância global do repositório em memória
db_repository = AppointmentMemoryRepository()


def get_db_repository() -> AppointmentMemoryRepository:
    """Função provedora de dependência do repositório de dados."""
    return db_repository
