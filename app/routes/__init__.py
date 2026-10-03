from app.routes.appointments import router as appointments_router
from app.routes.web import router as web_router
from app.routes.auth import router as auth_router
from app.routes.admin import router as admin_router
from app.routes.lab import router as lab_router

__all__ = [
    "appointments_router",
    "web_router",
    "auth_router",
    "admin_router",
    "lab_router",
]
