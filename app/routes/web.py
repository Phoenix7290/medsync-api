"""
Módulo de Rotas Web para a Recepção da Clínica (Exercício 2).

Decisões de Segurança e Arquitetura:
1. Renderização segura de HTML com Jinja2 usando templates com herança (base.html -> agenda.html).
2. O autoescape do Jinja2 é mantido ativado para todas as saídas HTML, neutralizando
   vetores de Cross-Site Scripting (Stored XSS) originados de dados de pacientes ou notas.
3. Não são enviados ao contexto HTML dados de auditoria interna (como IPs ou trace IDs).
"""

from pathlib import Path
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.database import get_db_repository, AppointmentMemoryRepository

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter(prefix="/recepcao", tags=["Portal Web da Recepção"])


@router.get("/agenda", response_class=HTMLResponse, summary="Visualizar agenda de consultas do dia")
async def view_agenda(
    request: Request,
    repo: AppointmentMemoryRepository = Depends(get_db_repository),
):
    """
    Renderiza a agenda do dia para a recepção das clínicas.
    Dados de entrada são higienizados contextualmente pelo Jinja2.
    """
    appointments = repo.list_all()
    return templates.TemplateResponse(
        request=request,
        name="agenda.html",
        context={"appointments": appointments}
    )
