import re
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from sqlmodel import Field as SQLField, SQLModel


class UserRole(str, Enum):
    RECEPTIONIST = "receptionist"
    DOCTOR = "doctor"
    ADMIN = "admin"
    PARTNER = "partner"


# ---------------------------------------------------------------------------
# Tabelas (SQLModel) — persistência de usuários e clientes M2M
# ---------------------------------------------------------------------------
class User(SQLModel, table=True):
    __tablename__: Any = "users"

    id: Optional[int] = SQLField(default=None, primary_key=True)
    username: str = SQLField(index=True, unique=True, min_length=3, max_length=50)
    email: str
    full_name: str
    role: UserRole
    hashed_password: str
    doctor_crm: Optional[str] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None


class PartnerClient(SQLModel, table=True):
    __tablename__: Any = "partner_clients"

    client_id: str = SQLField(primary_key=True, max_length=100)
    client_secret_hash: str
    allowed_scopes: str  # escopos separados por espaço (convenção OAuth 2.0)

    @property
    def scopes_list(self) -> List[str]:
        return self.allowed_scopes.split()


# Alias usado pelo restante do código
UserInDB = User


# ---------------------------------------------------------------------------
# Schemas de entrada/saída (Pydantic)
# ---------------------------------------------------------------------------
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: UserRole
    full_name: str = Field(..., min_length=2, max_length=100)


class UserCreate(BaseModel):
    """Entrada do cadastro de usuários (rota restrita a administradores com MFA)."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=100)
    role: UserRole
    password: str = Field(..., min_length=8, max_length=128)
    doctor_crm: Optional[str] = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,50}", v):
            raise ValueError("username aceita apenas letras, números, '_', '.' e '-'.")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-zÀ-ÖØ-öø-ÿ\s\.\'-]{2,100}", v):
            raise ValueError("full_name contém caracteres inválidos.")
        return v

    @field_validator("role")
    @classmethod
    def partner_is_not_a_user(cls, v: UserRole) -> UserRole:
        if v == UserRole.PARTNER:
            raise ValueError("O papel 'partner' é exclusivo de clientes M2M e não pode ser cadastrado aqui.")
        return v

    @model_validator(mode="after")
    def doctor_requires_valid_crm(self) -> "UserCreate":
        if self.role == UserRole.DOCTOR:
            if not self.doctor_crm or not re.fullmatch(r"CRM/[A-Z]{2}\s\d{4,6}", self.doctor_crm):
                raise ValueError("Profissionais de saúde exigem doctor_crm no formato 'CRM/UF XXXXXX'.")
        elif self.doctor_crm is not None:
            raise ValueError("doctor_crm só pode ser informado para o papel 'doctor'.")
        return self


class UserResponse(UserBase):
    id: int
    doctor_crm: Optional[str] = None

    model_config = {"from_attributes": True}


class UserCreatedResponse(UserResponse):
    # Entregue uma única vez na criação de contas administrativas (cadastro no autenticador).
    mfa_provisioning_secret: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    scopes: List[str] = []
    mfa_required: bool = False


class TokenPayload(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = None
    scopes: List[str] = []
    mfa_verified: bool = False
    doctor_crm: Optional[str] = None


class MFAVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mfa_code: str = Field(..., pattern=r"^\d{6}$")


class M2MTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: str = Field(..., min_length=1, max_length=100)
    client_secret: str = Field(..., min_length=1, max_length=256)
    grant_type: str = "client_credentials"
