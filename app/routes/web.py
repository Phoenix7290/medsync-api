from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from app.core.dependencies import require_roles
from app.database.session import get_session
from app.models.appointment import Appointment
from app.models.user import TokenPayload, UserRole

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter(prefix="/recepcao", tags=["Portal Web da Recepção"])


@router.get("/agenda", response_class=HTMLResponse, summary="Visualizar agenda de consultas do dia")
async def view_agenda(
    request: Request,
    _payload: TokenPayload = Depends(
        require_roles([UserRole.RECEPTIONIST, UserRole.ADMIN], ["appointments:read"])
    ),
    session: Session = Depends(get_session),
):
    statement = select(Appointment)
    appointments = session.exec(statement).all()
    return templates.TemplateResponse(
        request=request,
        name="agenda.html",
        context={"appointments": appointments},
    )
