"""Módulo de modelos da aplicação MedSync."""

from app.models.appointment import (
    AppointmentBase,
    AppointmentCreate,
    AppointmentResponse,
    AppointmentInternal,
)

__all__ = [
    "AppointmentBase",
    "AppointmentCreate",
    "AppointmentResponse",
    "AppointmentInternal",
]
