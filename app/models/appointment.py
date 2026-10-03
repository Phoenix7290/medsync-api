import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import ConfigDict, field_validator
from sqlmodel import Field as SQLField, SQLModel


class AppointmentBase(SQLModel):
    patient_name: str = SQLField(
        ...,
        min_length=2,
        max_length=100,
        description="Nome completo do paciente (validação por whitelist)",
    )
    patient_cpf: str = SQLField(
        ...,
        min_length=14,
        max_length=14,
        description="CPF no formato XXX.XXX.XXX-XX",
    )
    doctor_name: str = SQLField(..., min_length=2, max_length=100)
    doctor_crm: str = SQLField(
        ...,
        min_length=9,
        max_length=20,
        description="Registro profissional no formato CRM/UF XXXXXX",
    )
    appointment_datetime: datetime = SQLField(..., description="Data e hora da consulta")
    specialty: str = SQLField(..., min_length=2, max_length=50)
    status: str = SQLField(default="agendada")

    @field_validator("patient_cpf")
    @classmethod
    def validate_cpf_format(cls, v: str) -> str:
        pattern = r"^\d{3}\.\d{3}\.\d{3}-\d{2}$"
        if not re.match(pattern, v):
            raise ValueError("CPF deve seguir rigorosamente o padrão XXX.XXX.XXX-XX")
        return v

    @field_validator("doctor_crm")
    @classmethod
    def validate_crm_format(cls, v: str) -> str:
        pattern = r"^CRM/[A-Z]{2}\s\d{4,6}$"
        if not re.match(pattern, v):
            raise ValueError("CRM deve seguir o formato 'CRM/UF XXXXXX' (ex: 'CRM/SP 123456')")
        return v

    @field_validator("patient_name")
    @classmethod
    def validate_patient_name_whitelist(cls, v: str) -> str:
        pattern = r"^[A-Za-zÀ-ÖØ-öø-ÿ\s\.\'-]{2,100}$"
        if not re.match(pattern, v):
            raise ValueError("Nome do paciente contém caracteres inválidos. Apenas letras e acentos são permitidos.")
        return v


class AppointmentCreate(AppointmentBase):
    model_config: Any = ConfigDict(extra="forbid")


class AppointmentResponse(SQLModel):
    id: int
    patient_name: str
    doctor_name: str
    doctor_crm: str
    appointment_datetime: datetime
    specialty: str
    status: str

    model_config: Any = ConfigDict(from_attributes=True)


class Appointment(AppointmentBase, table=True):
    __tablename__: Any = "appointments"

    id: Optional[int] = SQLField(default=None, primary_key=True)
    internal_audit_id: str = SQLField(
        default_factory=lambda: f"AUDIT-{uuid.uuid4().hex[:12].upper()}",
        index=True,
    )
    created_by_ip: str = SQLField(default="127.0.0.1")
    internal_notes: Optional[str] = SQLField(default=None)
    created_at: datetime = SQLField(default_factory=lambda: datetime.now(timezone.utc))


AppointmentInternal = Appointment
