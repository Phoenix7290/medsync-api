from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
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
    data: Optional[date] = Query(default=None, description="Filtra por dia (AAAA-MM-DD). Sem valor: todas as datas."),
    limit: int = Query(default=100, ge=1, le=200, description="Máximo de linhas por página."),
    offset: int = Query(default=0, ge=0, description="Deslocamento para paginação."),
    _payload: TokenPayload = Depends(
        require_roles([UserRole.RECEPTIONIST, UserRole.ADMIN], ["appointments:read"])
    ),
    session: Session = Depends(get_session),
):
    statement = select(Appointment).order_by(Appointment.appointment_datetime)  # type: ignore[arg-type]
    if data is not None:
        day_start = datetime.combine(data, time.min, tzinfo=timezone.utc)
        statement = statement.where(
            Appointment.appointment_datetime >= day_start,
            Appointment.appointment_datetime < day_start + timedelta(days=1),
        )
    appointments = session.exec(statement.offset(offset).limit(limit)).all()
    return templates.TemplateResponse(
        request=request,
        name="agenda.html",
        context={"appointments": appointments, "data_ref": data, "limit": limit, "offset": offset},
    )
