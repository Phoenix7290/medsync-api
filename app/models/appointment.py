"""
Módulo de Modelos Pydantic para Consultas (Appointments).

Decisões de Segurança e Arquitetura:
1. Separação explícita entre esquemas de entrada (AppointmentCreate),
   esquemas internos completos com auditoria (AppointmentInternal) e
   esquemas de saída expostos externamente (AppointmentResponse).
2. Proteção contra Vazamento de Dados Sensíveis e Metadados Internos:
   Campos como 'internal_audit_id', 'created_by_ip' e 'internal_notes'
   existem na camada interna para rastreabilidade, mas são rigorosamente
   omitidos do 'AppointmentResponse'.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class AppointmentBase(BaseModel):
    """Atributos básicos compartilhados de uma consulta."""
    patient_name: str = Field(..., min_length=2, max_length=100, description="Nome completo do paciente")
    patient_cpf: str = Field(..., min_length=11, max_length=14, description="CPF do paciente (dado sensível LGPD)")
    doctor_name: str = Field(..., min_length=2, max_length=100, description="Nome do profissional de saúde")
    doctor_crm: str = Field(..., min_length=4, max_length=20, description="Registro profissional (CRM/COREN)")
    appointment_datetime: datetime = Field(..., description="Data e hora da consulta")
    specialty: str = Field(..., min_length=2, max_length=50, description="Especialidade médica")
    status: str = Field(default="agendada", description="Status da consulta")


class AppointmentCreate(AppointmentBase):
    """
    Payload de entrada para criação de agendamento de consulta.
    Campos de auditoria NÃO podem ser enviados pelo cliente externo.
    """
    pass


class AppointmentResponse(BaseModel):
    """
    Response Model seguro para clientes externos da API (Exercício 2).
    
    Apenas dados necessários para a confirmação do agendamento são expostos.
    O CPF do paciente é parcialmente mascarado ou exposto com parcimônia,
    e NENHUM metadado de auditoria interna (como IP, identificador de log ou
    notas internas) é incluído aqui.
    """
    id: int
    patient_name: str
    doctor_name: str
    doctor_crm: str
    appointment_datetime: datetime
    specialty: str
    status: str

    model_config = {
        "from_attributes": True
    }


class AppointmentInternal(AppointmentBase):
    """
    Entidade de persistência interna com campos de auditoria e governança.
    
    Esses campos NUNCA devem vazar nas respostas JSON de clientes externos,
    conforme exigência de segurança contra vazamento de metadados e enumeração.
    """
    id: int
    # Campos internos de auditoria e segurança
    internal_audit_id: str
    created_by_ip: str
    internal_notes: Optional[str] = None
    created_at: datetime
