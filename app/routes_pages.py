from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Subject, TimetableTemplate
from app.auth import get_current_user
from app.templates import templates

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("base.html", {"request": request})


@router.get("/timetable", response_class=HTMLResponse)
async def timetable(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    subjects = db.query(Subject).all()
    timetable_templates = db.query(TimetableTemplate).filter(
        TimetableTemplate.user_id == current_user.id
    ).order_by(TimetableTemplate.day_of_week, TimetableTemplate.lesson_number).all()

    return templates.TemplateResponse(
        "timetable.html",
        {
            "request": request,
            "user": current_user,
            "subjects": subjects,
            "templates": timetable_templates,
            "weekdays": ['Понедельник', 'Вторник', 'Среда', 'Четверг', 'Пятница', 'Суббота', 'Воскресенье']
        }
    )


@router.get("/rating", response_class=HTMLResponse)
async def rating(request: Request):
    return templates.TemplateResponse("rating.html", {"request": request})


@router.get("/diary-page", response_class=HTMLResponse)
async def diary_redirect():
    return RedirectResponse(url="/diary")