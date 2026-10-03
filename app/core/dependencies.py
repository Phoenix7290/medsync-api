from typing import List, Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
import jwt

from app.core.security import decode_access_token
from app.database.users import get_user_repository, UserMemoryRepository
from app.models.user import TokenPayload, UserInDB, UserRole

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
    user_repo: UserMemoryRepository = Depends(get_user_repository),
) -> UserInDB:
    if not payload.sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais de autenticação inválidas.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = user_repo.get_by_username(payload.sub)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário associado ao token não encontrado.",
        )
    return user


def require_roles(allowed_roles: List[UserRole]):
    def role_checker(payload: TokenPayload = Depends(get_current_token_payload)) -> TokenPayload:
        if payload.role not in [role.value for role in allowed_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acesso negado. Esta operação exige perfil: {[r.value for r in allowed_roles]}",
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
