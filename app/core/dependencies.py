from typing import Callable, List, Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from sqlmodel import Session, select

from app.core.security import decode_access_token
from app.database.session import get_session
from app.database.users import UserRepository, get_user_repository
from app.models.appointment import Appointment
from app.models.user import TokenPayload, User, UserRole

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/token",
    scopes={
        "appointments:read": "Ler dados completos de agendamentos",
        "appointments:write": "Criar e gerenciar agendamentos",
        "appointments:read_slots": "Consultar apenas horários e datas disponíveis",
        "admin:manage": "Gerenciamento administrativo do sistema",
    },
)


def get_current_token_payload(token: str = Depends(oauth2_scheme)) -> TokenPayload:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais de autenticação inválidas ou token expirado.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        username: Optional[str] = payload.get("sub")
        role: Optional[str] = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        return TokenPayload(
            sub=username,
            role=role,
            scopes=payload.get("scopes", []),
            mfa_verified=payload.get("mfa_verified", False),
            doctor_crm=payload.get("doctor_crm"),
        )
    except jwt.PyJWTError:
        raise credentials_exception


def get_current_user(
    payload: TokenPayload = Depends(get_current_token_payload),
    user_repo: UserRepository = Depends(get_user_repository),
) -> User:
    user = user_repo.get_by_username(payload.sub) if payload.sub else None
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário associado ao token não encontrado.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_roles(allowed_roles: List[UserRole], required_scopes: Optional[List[str]] = None):
    """Autorização centralizada: exige PAPEL permitido E (opcionalmente) escopos no token.

    Um token M2M (role=partner) nunca passa aqui, a menos que 'partner' seja listado.
    """
    allowed = [role.value for role in allowed_roles]

    def role_checker(payload: TokenPayload = Depends(get_current_token_payload)) -> TokenPayload:
        if payload.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso negado. Seu perfil não tem permissão para esta operação.",
            )
        for scope in required_scopes or []:
            if scope not in payload.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Escopo insuficiente. O token requer o escopo '{scope}'.",
                    headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope}"'},
                )
        return payload

    return role_checker


def require_admin_with_mfa(payload: TokenPayload = Depends(get_current_token_payload)) -> TokenPayload:
    if payload.role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado. Recurso restrito a administradores.",
        )
    if not payload.mfa_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operação administrativa requer autenticação multifator (MFA) verificada.",
        )
    return payload


def verify_oauth2_scopes(
    security_scopes: SecurityScopes,
    payload: TokenPayload = Depends(get_current_token_payload),
) -> TokenPayload:
    for scope in security_scopes.scopes:
        if scope not in payload.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Escopo insuficiente. O token requer o escopo '{scope}'.",
                headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope}"'},
            )
    return payload


# ---------------------------------------------------------------------------
# Ownership (BOLA) — ÚNICO ponto onde a regra "médico só acessa o próprio CRM" existe.
# ---------------------------------------------------------------------------
def enforce_appointment_ownership(payload: TokenPayload, doctor_crm: str) -> None:
    """Médicos só acessam consultas do próprio CRM; token de médico sem CRM é negado."""
    if payload.role == UserRole.DOCTOR.value:
        if not payload.doctor_crm or payload.doctor_crm != doctor_crm:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acesso negado. Você só tem permissão para operar consultas sob o seu próprio CRM.",
            )


def appointment_access(roles: List[UserRole], scope: str) -> Callable[..., Appointment]:
    """Fábrica de dependência: autentica, autoriza (papel+escopo), busca a consulta e valida ownership."""

    def dependency(
        appointment_id: int,
        payload: TokenPayload = Depends(require_roles(roles, [scope])),
        session: Session = Depends(get_session),
    ) -> Appointment:
        statement = select(Appointment).where(Appointment.id == appointment_id)
        appointment = session.exec(statement).first()
        if not appointment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Consulta com ID {appointment_id} não encontrada.",
            )
        enforce_appointment_ownership(payload, appointment.doctor_crm)
        return appointment

    return dependency


# Quem pode LER consultas (médico: só as suas; recepção/admin: todas).
get_readable_appointment = appointment_access(
    [UserRole.DOCTOR, UserRole.RECEPTIONIST, UserRole.ADMIN], "appointments:read"
)
# Quem pode GERENCIAR (apagar) consultas: apenas profissionais de saúde, nas próprias.
get_manageable_appointment = appointment_access([UserRole.DOCTOR], "appointments:write")
