from app.models.appointment import (
    AppointmentBase,
    AppointmentCreate,
    AppointmentResponse,
    Appointment,
)
from app.models.user import (
    UserRole,
    UserBase,
    UserCreate,
    UserResponse,
    UserCreatedResponse,
    UserInDB,
    User,
    PartnerClient,
    Token,
    TokenPayload,
    MFAVerifyRequest,
    M2MTokenRequest,
)

AppointmentInternal = Appointment

__all__ = [
    "AppointmentBase",
    "AppointmentCreate",
    "AppointmentResponse",
    "Appointment",
    "AppointmentInternal",
    "UserRole",
    "UserBase",
    "UserCreate",
    "UserResponse",
    "UserCreatedResponse",
    "UserInDB",
    "User",
    "PartnerClient",
    "Token",
    "TokenPayload",
    "MFAVerifyRequest",
    "M2MTokenRequest",
]
