"""
Модуль дополнительных API-маршрутов для дневника, в частности для
генерации уроков из шаблона расписания.
"""

from datetime import date, timedelta
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import logging

from app.database import get_db
from app.models import User, Lesson, TimetableTemplate
from app.auth import get_current_user

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/diary/api/generate-from-template")
async def generate_lessons_from_template(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Генерирует уроки на ближайшие 14 дней на основе шаблона расписания пользователя.
    Если урок уже существует, обновляет его (предмет, время, кабинет).
    Возвращает количество созданных/обновлённых уроков.
    """
    try:
        templates = db.query(TimetableTemplate).filter(
            TimetableTemplate.user_id == current_user.id
        ).all()

        if not templates:
            return JSONResponse({
                "success": False,
                "error": "У вас нет шаблонов расписания"
            })

        start_date = date.today()
        end_date = start_date + timedelta(days=14)

        generated_count = 0
        current_date = start_date

        while current_date <= end_date:
            day_of_week = current_date.weekday()
            day_templates = [t for t in templates if t.day_of_week == day_of_week]

            for template in day_templates:
                existing_lesson = db.query(Lesson).filter(
                    Lesson.user_id == current_user.id,
                    Lesson.date == current_date,
                    Lesson.lesson_number == template.lesson_number
                ).first()

                if existing_lesson:
                    # Обновляем существующий урок
                    existing_lesson.subject_id = template.subject_id
                    existing_lesson.start_time = template.start_time
                    existing_lesson.end_time = template.end_time
                    existing_lesson.room = template.room
                else:
                    # Создаём новый урок
                    new_lesson = Lesson(
                        user_id=current_user.id,
                        subject_id=template.subject_id,
                        date=current_date,
                        lesson_number=template.lesson_number,
                        start_time=template.start_time,
                        end_time=template.end_time,
                        room=template.room
                    )
                    db.add(new_lesson)
                    generated_count += 1

            current_date += timedelta(days=1)

        db.commit()

        return JSONResponse({
            "success": True,
            "generated": generated_count,
            "message": f"Уроки успешно созданы на период с {start_date} по {end_date}"
        })

    except Exception as e:
        db.rollback()
        logger.error(f"Ошибка при генерации уроков: {e}", exc_info=True)
        return JSONResponse({
            "success": False,
            "error": str(e)
        }, status_code=500)