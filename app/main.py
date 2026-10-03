from fastapi import FastAPI
from app.routes.appointments import router as appointments_router
from app.routes.web import router as web_router
from app.routes.auth import router as auth_router
from app.routes.admin import router as admin_router
from app.routes.lab import router as lab_router

app = FastAPI(
    title="MedSync API - Agendamento Seguro de Consultas",
    description=(
        "API RESTful de alta segurança para gerenciamento de agendamentos médicos, "
        "atendendo clínicas, recepção e parceiros laboratoriais em conformidade com a LGPD."
    ),
    version="1.0.0",
)

app.include_router(auth_router)
app.include_router(appointments_router)
app.include_router(admin_router)
app.include_router(lab_router)
app.include_router(web_router)


@app.get("/", tags=["Healthcheck"])
async def root():
    return {
        "status": "online",
        "service": "MedSync API",
        "version": "1.0.0",
        "docs_url": "/docs",
    }
