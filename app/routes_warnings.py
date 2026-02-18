from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .database import get_db
from .models import User, Lesson, Subject
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
    try:
        now = datetime.utcnow()
        tomorrow = now + timedelta(days=1)

        lessons = db.query(Lesson).filter(
            Lesson.user_id == current_user.id,
            Lesson.date >= now.date(),
            Lesson.date <= tomorrow.date(),
            Lesson.homework != None,
            Lesson.homework != ''
        ).order_by(Lesson.date, Lesson.lesson_number).all()

        subject_names = {}
        if lessons:
            subject_ids = {l.subject_id for l in lessons}
            subjects = db.query(Subject).filter(Subject.id.in_(subject_ids)).all()
            subject_names = {s.id: s.name for s in subjects}

        result = []
        for lesson in lessons:
            subject_name = subject_names.get(lesson.subject_id, "Неизвестный предмет")
            result.append({
                "id": lesson.id,
                "subject": subject_name,
                "homework": lesson.homework,
                "date": lesson.date.isoformat(),
                "lesson_number": lesson.lesson_number
            })

        return result

    except Exception as e:
        print(f"Ошибка в upcoming_reminders: {e}")
        return []