from typing import Any, List

from fastapi import APIRouter, Depends, Request, status
from sqlmodel import Session, select

from app.core.dependencies import (
    enforce_appointment_ownership,
    get_manageable_appointment,
    get_readable_appointment,
    require_roles,
)
from app.database.session import get_session
from app.models.appointment import Appointment, AppointmentCreate, AppointmentResponse
from app.models.user import TokenPayload, UserRole

router = APIRouter(prefix="/appointments", tags=["Consultas"])

READ_ROLES = [UserRole.DOCTOR, UserRole.RECEPTIONIST, UserRole.ADMIN]


@router.post(
    "/",
    response_model=AppointmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar novo agendamento de consulta (apenas profissionais de saúde)",
)
async def create_appointment(
    data: AppointmentCreate,
    request: Request,
    payload: TokenPayload = Depends(require_roles([UserRole.DOCTOR], ["appointments:write"])),
    session: Session = Depends(get_session),
) -> Any:
    enforce_appointment_ownership(payload, data.doctor_crm)

    client_ip = request.client.host if request.client else "unknown"
    record = Appointment(
        patient_name=data.patient_name,
        patient_cpf=data.patient_cpf,
        doctor_name=data.doctor_name,
        doctor_crm=data.doctor_crm,
        appointment_datetime=data.appointment_datetime,
        specialty=data.specialty,
        status=data.status,
        created_by_ip=client_ip,
        internal_notes="Criado via API autenticada",
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return record


@router.get(
    "/",
    response_model=List[AppointmentResponse],
    summary="Listar consultas com controle de acesso",
)
async def list_appointments(
    payload: TokenPayload = Depends(require_roles(READ_ROLES, ["appointments:read"])),
    session: Session = Depends(get_session),
) -> Any:
    statement = select(Appointment)
    if payload.role == UserRole.DOCTOR.value:
        # Médico sem CRM no token enxerga lista vazia (nunca "tudo").
        statement = statement.where(Appointment.doctor_crm == (payload.doctor_crm or ""))
    return list(session.exec(statement).all())


@router.get(
    "/{appointment_id}",
    response_model=AppointmentResponse,
    summary="Obter detalhes de uma consulta por ID",
)
async def get_appointment(
    appointment: Appointment = Depends(get_readable_appointment),
) -> Any:
    return appointment


@router.delete(
    "/{appointment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancelar/remover agendamento de consulta (apenas o médico responsável)",
)
async def delete_appointment(
    appointment: Appointment = Depends(get_manageable_appointment),
    session: Session = Depends(get_session),
) -> None:
    session.delete(appointment)
    session.commit()
