"""Módulo de rotas da aplicação MedSync."""

from app.routes.appointments import router as appointments_router
from app.routes.web import router as web_router

__all__ = ["appointments_router", "web_router"]
