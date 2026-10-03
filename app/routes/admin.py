from fastapi import APIRouter, Depends
from app.core.dependencies import require_admin_with_mfa
from app.models.user import TokenPayload

router = APIRouter(prefix="/admin", tags=["Administração"])


@router.get("/audit-logs", summary="Visualizar trilha de auditoria do sistema")
async def get_system_audit_logs(
    admin_payload: TokenPayload = Depends(require_admin_with_mfa),
):
    return {
        "status": "success",
        "authorized_admin": admin_payload.sub,
        "mfa_verified": admin_payload.mfa_verified,
        "logs": [
            {"event": "AUTH_SUCCESS", "user": "admin", "ip": "10.0.0.1"},
            {"event": "CONFIG_UPDATE", "user": "admin", "detail": "Security policies enforced"},
        ],
    }
