"""
Модуль маршрутов для взаимодействия с AI-помощником (Groq API).
Предоставляет эндпоинты для помощи с домашним заданием и общих запросов.
"""

import logging
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Lesson
from app.auth import get_current_user
from app.ai_funcs import ask_support
from app.schemas import HomeworkHelpRequest, AIRequest

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/api/help-with-homework")
async def help_with_homework(
        request: Request,
        help_req: HomeworkHelpRequest,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Эндпоинт для получения объяснения домашнего задания из конкретного урока.
    Принимает идентификатор урока, извлекает текст домашнего задания и отправляет его в AI.
    Возвращает объяснение.
    """
    lesson = db.query(Lesson).filter(
        Lesson.id == help_req.lesson_id,
        Lesson.user_id == current_user.id
    ).first()
    if not lesson:
        raise HTTPException(status_code=404, detail="Урок не найден")

    if not lesson.homework:
        return JSONResponse({
            "success": False,
            "error": "Для этого урока не указано домашнее задание"
        })

    try:
        explanation = ask_support(lesson.homework)
        return JSONResponse({
            "success": True,
            "homework": lesson.homework,
            "explanation": explanation
        })
    except Exception as e:
        logger.error(f"Ошибка при вызове нейросети: {e}", exc_info=True)
        return JSONResponse({
            "success": False,
            "error": "Не удалось получить объяснение. Попробуйте позже."
        }, status_code=500)


@router.post("/api/ask-ai")
async def ask_ai(
        request: Request,
        ai_req: AIRequest,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Универсальный эндпоинт для обращения к AI.
    Можно передать либо lesson_id (тогда используется текст ДЗ из урока),
    либо произвольный текст в поле text.
    Возвращает ответ модели.
    """
    prompt = None
    if ai_req.lesson_id:
        lesson = db.query(Lesson).filter(
            Lesson.id == ai_req.lesson_id,
            Lesson.user_id == current_user.id
        ).first()
        if not lesson:
            raise HTTPException(status_code=404, detail="Урок не найден")
        if not lesson.homework:
            return JSONResponse({
                "success": False,
                "error": "Для этого урока не указано домашнее задание"
            })
        prompt = lesson.homework
    elif ai_req.text:
        prompt = ai_req.text
    else:
        raise HTTPException(status_code=400, detail="Необходимо указать lesson_id или text")

    try:
        explanation = ask_support(prompt)
        return JSONResponse({
            "success": True,
            "explanation": explanation
        })
    except Exception as e:
        logger.error(f"Ошибка при вызове нейросети: {e}", exc_info=True)
        return JSONResponse({
            "success": False,
            "error": "Не удалось получить объяснение. Попробуйте позже."
        }, status_code=500)