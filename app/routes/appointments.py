from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session, select

from app.core.dependencies import get_current_token_payload
from app.database.session import get_session
from app.models.appointment import Appointment, AppointmentCreate, AppointmentResponse
from app.models.user import TokenPayload, UserRole

router = APIRouter(prefix="/appointments", tags=["Consultas"])


@router.post(
    "/",
    response_model=AppointmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Criar novo agendamento de consulta",
)
async def create_appointment(
    data: AppointmentCreate,
    request: Request,
    payload: TokenPayload = Depends(get_current_token_payload),
    session: Session = Depends(get_session),
) -> Any:
    if payload.role == UserRole.DOCTOR.value:
        if payload.doctor_crm and data.doctor_crm != payload.doctor_crm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Profissionais de saúde só podem criar consultas para o seu próprio CRM.",
            )

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
    payload: TokenPayload = Depends(get_current_token_payload),
    session: Session = Depends(get_session),
) -> Any:
    if payload.role == UserRole.DOCTOR.value:
        statement = select(Appointment).where(Appointment.doctor_crm == payload.doctor_crm)
    else:
        statement = select(Appointment)
    
    results = session.exec(statement).all()
    return list(results)


@router.get(
    "/{appointment_id}",
    response_model=AppointmentResponse,
    summary="Obter detalhes de uma consulta por ID",
)
async def get_appointment(
    appointment_id: int,
    payload: TokenPayload = Depends(get_current_token_payload),
    session: Session = Depends(get_session),
) -> Any:
    statement = select(Appointment).where(Appointment.id == appointment_id)
    appointment = session.exec(statement).first()
    if not appointment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Consulta com ID {appointment_id} não encontrada.",
        )

    if payload.role == UserRole.DOCTOR.value:
        if payload.doctor_crm and appointment.doctor_crm != payload.doctor_crm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso negado. Você só tem permissão para visualizar consultas sob seu CRM.",
            )

    return appointment


@router.delete(
    "/{appointment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancelar/remover agendamento de consulta",
)
async def delete_appointment(
    appointment_id: int,
    payload: TokenPayload = Depends(get_current_token_payload),
    session: Session = Depends(get_session),
) -> None:
    statement = select(Appointment).where(Appointment.id == appointment_id)
    appointment = session.exec(statement).first()
    if not appointment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Consulta com ID {appointment_id} não encontrada para remoção.",
        )

    if payload.role == UserRole.DOCTOR.value:
        if payload.doctor_crm and appointment.doctor_crm != payload.doctor_crm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso negado. Você só tem permissão para cancelar consultas sob seu CRM.",
            )

    session.delete(appointment)
    session.commit()
