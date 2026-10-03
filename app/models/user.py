from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    RECEPTIONIST = "receptionist"
    DOCTOR = "doctor"
    ADMIN = "admin"
    PARTNER = "partner"


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: UserRole
    full_name: str = Field(..., min_length=2, max_length=100)


class UserCreate(UserBase):
    password: str = Field(..., min_length=6)
    doctor_crm: Optional[str] = None


class UserResponse(UserBase):
    id: int
    doctor_crm: Optional[str] = None

    model_config = {"from_attributes": True}


class UserInDB(UserBase):
    id: int
    hashed_password: str
    doctor_crm: Optional[str] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None


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
    username: str
    mfa_code: str = Field(..., min_length=6, max_length=6)


class M2MTokenRequest(BaseModel):
    client_id: str
    client_secret: str
    grant_type: str = "client_credentials"
