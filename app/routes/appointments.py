from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.dependencies import get_current_token_payload
from app.database import get_db_repository, AppointmentMemoryRepository
from app.models.appointment import AppointmentCreate, AppointmentResponse
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
    repo: AppointmentMemoryRepository = Depends(get_db_repository),
) -> AppointmentResponse:
    if payload.role == UserRole.DOCTOR.value:
        if payload.doctor_crm and data.doctor_crm != payload.doctor_crm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Profissionais de saúde só podem criar consultas para o seu próprio CRM.",
            )

    client_ip = request.client.host if request.client else "unknown"
    record = repo.create(data, client_ip=client_ip)
    return record


@router.get(
    "/",
    response_model=List[AppointmentResponse],
    summary="Listar consultas com controle de acesso",
)
async def list_appointments(
    payload: TokenPayload = Depends(get_current_token_payload),
    repo: AppointmentMemoryRepository = Depends(get_db_repository),
) -> List[AppointmentResponse]:
    all_appointments = repo.list_all()
    if payload.role == UserRole.DOCTOR.value:
        return [app for app in all_appointments if app.doctor_crm == payload.doctor_crm]
    return all_appointments


@router.get(
    "/{appointment_id}",
    response_model=AppointmentResponse,
    summary="Obter detalhes de uma consulta por ID",
)
async def get_appointment(
    appointment_id: int,
    payload: TokenPayload = Depends(get_current_token_payload),
    repo: AppointmentMemoryRepository = Depends(get_db_repository),
) -> AppointmentResponse:
    appointment = repo.get_by_id(appointment_id)
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
    repo: AppointmentMemoryRepository = Depends(get_db_repository),
) -> None:
    appointment = repo.get_by_id(appointment_id)
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

    repo.delete(appointment_id)
