"""
Ponto de Entrada Principal da Aplicação MedSync (Exercícios 1 e 2).

Decisões de Arquitetura:
1. Aplicação FastAPI modularizada com agregação dos roteadores via APIRouter.
2. Metadados de OpenAPI descritivos com documentação de segurança.
3. Inclusão dos roteadores de API REST (/appointments) e Portal Web (/recepcao).
"""

from fastapi import FastAPI
from app.routes.appointments import router as appointments_router
from app.routes.web import router as web_router

app = FastAPI(
    title="MedSync API - Agendamento Seguro de Consultas",
    description=(
        "API RESTful de alta segurança para gerenciamento de agendamentos médicos, "
        "atendendo clínicas, recepção e parceiros laboratoriais em conformidade com a LGPD."
    ),
    version="1.0.0",
)

# Acoplamento modular de rotas via APIRouter
app.include_router(appointments_router)
app.include_router(web_router)


@app.get("/", tags=["Healthcheck"])
async def root():
    """Endpoint raiz para verificação de disponibilidade da aplicação."""
    return {
        "status": "online",
        "service": "MedSync API",
        "version": "1.0.0",
        "docs_url": "/docs",
    }
