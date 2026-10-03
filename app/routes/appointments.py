"""
Módulo de Rotas RESTful para Consultas (Appointments) - Exercícios 1 e 2.

Decisões de Segurança e Arquitetura:
1. Modularização via APIRouter, desacoplando o recurso do entrypoint da aplicação.
2. Controle Estrito de Exposição (Exercício 2):
   O uso de 'response_model=AppointmentResponse' garante que a serialização JSON
   remova automaticamente os campos internos de auditoria (como 'internal_audit_id',
   'created_by_ip' e 'internal_notes') antes que o payload saia da fronteira de
   confiança da API.
3. Rastreabilidade e Auditoria: O endereço IP de origem do cliente e metadados
   são capturados no momento do cadastro e armazenados na entidade interna,
   sem contudo vazar para o cliente que fez a requisição.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.database import get_db_repository, AppointmentMemoryRepository
from app.models.appointment import AppointmentCreate, AppointmentResponse

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
    repo: AppointmentMemoryRepository = Depends(get_db_repository),
) -> AppointmentResponse:
    """
    Cadastra uma nova consulta no sistema.
    
    Campos de auditoria interna são injetados pelo backend e omitidos
    da resposta JSON através do response_model AppointmentResponse.
    """
    client_ip = request.client.host if request.client else "unknown"
    record = repo.create(data, client_ip=client_ip)
    return record


@router.get(
    "/",
    response_model=List[AppointmentResponse],
    summary="Listar todas as consultas",
)
async def list_appointments(
    repo: AppointmentMemoryRepository = Depends(get_db_repository),
) -> List[AppointmentResponse]:
    """
    Retorna a lista de consultas cadastradas com filtragem de campos internos.
    """
    return repo.list_all()


@router.get(
    "/{appointment_id}",
    response_model=AppointmentResponse,
    summary="Obter detalhes de uma consulta por ID",
)
async def get_appointment(
    appointment_id: int,
    repo: AppointmentMemoryRepository = Depends(get_db_repository),
) -> AppointmentResponse:
    """
    Busca uma consulta específica pelo seu ID.
    Lança HTTP 404 se não for encontrada.
    """
    appointment = repo.get_by_id(appointment_id)
    if not appointment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Consulta com ID {appointment_id} não encontrada."
        )
    return appointment


@router.delete(
    "/{appointment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancelar/remover agendamento de consulta",
)
async def delete_appointment(
    appointment_id: int,
    repo: AppointmentMemoryRepository = Depends(get_db_repository),
) -> None:
    """
    Remove uma consulta do sistema pelo seu identificador.
    """
    success = repo.delete(appointment_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Consulta com ID {appointment_id} não encontrada para remoção."
        )
