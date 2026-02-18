from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .database import get_db
from .models import User, Lesson
from .auth import get_current_user

router = APIRouter()

@router.get("/api/reminders/upcoming")
async def upcoming_reminders(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает список уроков текущего пользователя с домашним заданием,
    дата которых находится в ближайшие 24 часа.
    """
    now = datetime.utcnow()
    tomorrow = now + timedelta(days=1)

    lessons = db.query(Lesson).filter(
        Lesson.user_id == current_user.id,
        Lesson.date >= now.date(),
        Lesson.date <= tomorrow.date(),
        Lesson.homework != None,
        Lesson.homework != ''
    ).order_by(Lesson.date, Lesson.lesson_number).all()

    return [
        {
            "id": lesson.id,
            "subject": lesson.subject.name,
            "homework": lesson.homework,
            "date": lesson.date.isoformat(),
            "lesson_number": lesson.lesson_number
        }
        for lesson in lessons
    ]