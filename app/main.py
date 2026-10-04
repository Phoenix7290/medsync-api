from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.middleware import SecurityHeadersMiddleware
from app.database.session import init_db
from app.routes.admin import router as admin_router
from app.routes.appointments import router as appointments_router
from app.routes.auth import router as auth_router
from app.routes.lab import router as lab_router
from app.routes.web import router as web_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


# Em produção a documentação interativa e o schema OpenAPI não são expostos publicamente
# (reduz a superfície de reconhecimento; ver Ex. 13, auditoria OpenAPI).
_is_production = settings.ENVIRONMENT.strip().lower() == "production"

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "API RESTful de alta segurança para gerenciamento de agendamentos médicos, "
        "atendendo clínicas, recepção e parceiros laboratoriais em conformidade com a LGPD."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth_router)
app.include_router(appointments_router)
app.include_router(admin_router)
app.include_router(lab_router)
app.include_router(web_router)


@app.get("/", tags=["Healthcheck"])
async def root():
    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": "1.0.0",
        "docs_url": "/docs",
    }
