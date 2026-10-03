from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.config import settings
from app.core.middleware import login_rate_limiter
from app.core.security import create_access_token, verify_password
from app.database.users import get_user_repository, UserMemoryRepository
from app.models.user import (
    M2MTokenRequest,
    MFAVerifyRequest,
    Token,
    UserCreate,
    UserResponse,
    UserRole,
)

router = APIRouter(prefix="/auth", tags=["Autenticação e Tokens"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, summary="Cadastrar novo usuário no sistema")
async def register_user(
    user_in: UserCreate,
    user_repo: UserMemoryRepository = Depends(get_user_repository),
) -> UserResponse:
    existing_user = user_repo.get_by_username(user_in.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nome de usuário já está em uso.",
        )
    return user_repo.create_user(user_in)


@router.post("/token", response_model=Token, summary="Login OAuth2 Password Flow com Rate Limiting")
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_repo: UserMemoryRepository = Depends(get_user_repository),
) -> Token:
    client_ip = request.client.host if request.client else "127.0.0.1"
    if login_rate_limiter.is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas de login. Limite de requisições excedido. Tente novamente em instantes.",
            headers={"Retry-After": "60"},
        )

    user = user_repo.get_by_username(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nome de usuário ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scopes = []
    if user.role == UserRole.ADMIN:
        scopes = ["admin:manage", "appointments:read", "appointments:write"]
    elif user.role in (UserRole.DOCTOR, UserRole.RECEPTIONIST):
        scopes = ["appointments:read", "appointments:write"]

    token_data = {
        "sub": user.username,
        "role": user.role.value,
        "scopes": scopes,
        "mfa_verified": False,
    }
    if user.doctor_crm:
        token_data["doctor_crm"] = user.doctor_crm

    access_token = create_access_token(token_data)
    return Token(
        access_token=access_token,
        token_type="bearer",
        role=user.role.value,
        scopes=scopes,
        mfa_required=user.mfa_enabled,
    )


@router.post("/mfa/verify", response_model=Token, summary="Verificação de MFA para Administradores")
async def verify_mfa(
    mfa_in: MFAVerifyRequest,
    user_repo: UserMemoryRepository = Depends(get_user_repository),
) -> Token:
    user = user_repo.get_by_username(mfa_in.username)
    if not user or user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário administrador não encontrado.",
        )

    expected_secret = user.mfa_secret or settings.MFA_SECRET_DEV
    if mfa_in.mfa_code != expected_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código de autenticação em dois fatores (MFA) inválido.",
        )

    scopes = ["admin:manage", "appointments:read", "appointments:write"]
    token_data = {
        "sub": user.username,
        "role": user.role.value,
        "scopes": scopes,
        "mfa_verified": True,
    }
    elevated_token = create_access_token(token_data)
    return Token(
        access_token=elevated_token,
        token_type="bearer",
        role=user.role.value,
        scopes=scopes,
        mfa_required=False,
    )


@router.post("/m2m/token", response_model=Token, summary="OAuth2 Client Credentials para Integrações M2M (Laboratório)")
async def m2m_token_exchange(
    m2m_in: M2MTokenRequest,
    user_repo: UserMemoryRepository = Depends(get_user_repository),
) -> Token:
    if m2m_in.grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="grant_type inválido. Esperado 'client_credentials'.",
        )

    is_valid = user_repo.verify_partner_credentials(m2m_in.client_id, m2m_in.client_secret)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client credentials inválidas para parceiro M2M.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    partner = user_repo.get_partner(m2m_in.client_id)
    token_data = {
        "sub": partner.client_id,
        "role": UserRole.PARTNER.value,
        "scopes": partner.allowed_scopes,
        "mfa_verified": False,
    }
    partner_token = create_access_token(token_data)
    return Token(
        access_token=partner_token,
        token_type="bearer",
        role=UserRole.PARTNER.value,
        scopes=partner.allowed_scopes,
        mfa_required=False,
    )
