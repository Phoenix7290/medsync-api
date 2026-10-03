from typing import List
from fastapi import APIRouter, Security
from app.core.dependencies import verify_oauth2_scopes
from app.models.user import TokenPayload

router = APIRouter(prefix="/lab", tags=["Integração Laboratório Parceiro (M2M)"])


@router.get("/available-slots", summary="Consultar horários disponíveis para exames e consultas")
async def get_available_slots(
    payload: TokenPayload = Security(verify_oauth2_scopes, scopes=["appointments:read_slots"]),
):
    return {
        "client_id": payload.sub,
        "available_slots": [
            {"date": "2026-10-06", "time": "08:00", "specialty": "Cardiologia", "doctor": "Dr. Roberto Silva"},
            {"date": "2026-10-06", "time": "09:00", "specialty": "Cardiologia", "doctor": "Dr. Roberto Silva"},
            {"date": "2026-10-06", "time": "14:00", "specialty": "Dermatologia", "doctor": "Dra. Beatriz Santos"},
        ],
    }


@router.post("/manage-patients", summary="Ação restrita fora do escopo do laboratório")
async def restricted_lab_action(
    payload: TokenPayload = Security(verify_oauth2_scopes, scopes=["appointments:write"]),
):
    return {"message": "Acesso concedido"}
