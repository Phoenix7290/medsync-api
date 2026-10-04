from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.dependencies import get_current_token_payload, get_current_user, require_admin_with_mfa
from app.core.middleware import login_rate_limiter, mfa_rate_limiter
from app.core.security import ROLE_SCOPES, create_access_token, verify_totp
from app.database.users import UserRepository, get_user_repository
from app.models.user import (
    M2MTokenRequest,
    MFAVerifyRequest,
    Token,
    TokenPayload,
    User,
    UserCreate,
    UserCreatedResponse,
    UserRole,
)

router = APIRouter(prefix="/auth", tags=["Autenticação e Tokens"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "127.0.0.1"


@router.post(
    "/register",
    response_model=UserCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cadastrar novo usuário (somente administrador com MFA verificado)",
)
async def register_user(
    user_in: UserCreate,
    _admin: TokenPayload = Depends(require_admin_with_mfa),
    user_repo: UserRepository = Depends(get_user_repository),
) -> UserCreatedResponse:
    if user_repo.get_by_username(user_in.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nome de usuário já está em uso.",
        )
    created = user_repo.create_user(user_in)
    return UserCreatedResponse(
        id=created.id,  # type: ignore[arg-type]
        username=created.username,
        email=created.email,
        role=created.role,
        full_name=created.full_name,
        doctor_crm=created.doctor_crm,
        mfa_provisioning_secret=created.mfa_secret if created.mfa_enabled else None,
    )


@router.post("/token", response_model=Token, summary="Login OAuth2 Password Flow com Rate Limiting")
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    user_repo: UserRepository = Depends(get_user_repository),
) -> Token:
    if login_rate_limiter.is_rate_limited(_client_ip(request)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas de login. Limite de requisições excedido. Tente novamente em instantes.",
            headers={"Retry-After": "60"},
        )

    user = user_repo.authenticate(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nome de usuário ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scopes = ROLE_SCOPES.get(user.role.value, [])
    token_data = {
        "sub": user.username,
        "role": user.role.value,
        "scopes": scopes,
        "mfa_verified": False,
    }
    if user.doctor_crm:
        token_data["doctor_crm"] = user.doctor_crm

    return Token(
        access_token=create_access_token(token_data),
        role=user.role.value,
        scopes=scopes,
        mfa_required=user.mfa_enabled,
    )


@router.post("/mfa/verify", response_model=Token, summary="Segundo fator (TOTP) para contas com MFA")
async def verify_mfa(
    request: Request,
    mfa_in: MFAVerifyRequest,
    payload: TokenPayload = Depends(get_current_token_payload),
    user: User = Depends(get_current_user),
) -> Token:
    """Exige o token do 1º fator (senha). O código sozinho nunca emite token."""
    if mfa_rate_limiter.is_rate_limited(f"{_client_ip(request)}:{payload.sub}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas de verificação MFA. Tente novamente em instantes.",
            headers={"Retry-After": "60"},
        )

    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA não está habilitado para esta conta.",
        )

    if not verify_totp(user.mfa_secret, mfa_in.mfa_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código de autenticação em dois fatores (MFA) inválido.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scopes = ROLE_SCOPES.get(user.role.value, [])
    token_data = {
        "sub": user.username,
        "role": user.role.value,
        "scopes": scopes,
        "mfa_verified": True,
    }
    if user.doctor_crm:
        token_data["doctor_crm"] = user.doctor_crm

    return Token(
        access_token=create_access_token(token_data),
        role=user.role.value,
        scopes=scopes,
        mfa_required=False,
    )


@router.post("/m2m/token", response_model=Token, summary="OAuth2 Client Credentials para Integrações M2M (Laboratório)")
async def m2m_token_exchange(
    request: Request,
    m2m_in: M2MTokenRequest,
    user_repo: UserRepository = Depends(get_user_repository),
) -> Token:
    if m2m_in.grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="grant_type inválido. Esperado 'client_credentials'.",
        )

    if login_rate_limiter.is_rate_limited(f"m2m:{_client_ip(request)}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas. Limite de requisições excedido.",
            headers={"Retry-After": "60"},
        )

    partner = user_repo.authenticate_partner(m2m_in.client_id, m2m_in.client_secret)
    if not partner:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client credentials inválidas para parceiro M2M.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scopes = partner.scopes_list
    token_data = {
        "sub": partner.client_id,
        "role": UserRole.PARTNER.value,
        "scopes": scopes,
        "mfa_verified": False,
    }
    return Token(
        access_token=create_access_token(token_data),
        role=UserRole.PARTNER.value,
        scopes=scopes,
        mfa_required=False,
    )
