"""
Модуль маршрутов для трекера настроения.
Позволяет сохранять записи о настроении, получать историю и получать
персонализированные советы от AI на основе комментариев.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List
import asyncio

from . import models, schemas
from .auth import get_current_user
from .database import get_db
from .ai_funcs import ask_support

router = APIRouter(prefix="/api/mood", tags=["mood"])


@router.post("/entry", response_model=schemas.MoodEntryOut)
def create_mood_entry(
        entry: schemas.MoodEntryCreate,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Сохраняет запись о настроении пользователя.
    Принимает настроение (happy/neutral/sad), время дня (morning/afternoon/evening)
    и опциональный комментарий.
    """
    db_entry = models.MoodEntry(
        user_id=current_user.id,
        mood=entry.mood.value,
        time_of_day=entry.time_of_day.value,
        comment=entry.comment
    )
    db.add(db_entry)
    db.commit()
    db.refresh(db_entry)
    return db_entry


@router.get("/entries", response_model=List[schemas.MoodEntryOut])
def get_mood_entries(
        days: int = 7,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Возвращает записи настроения за последние N дней (по умолчанию 7).
    """
    since = datetime.utcnow() - timedelta(days=days)
    entries = db.query(models.MoodEntry).filter(
        models.MoodEntry.user_id == current_user.id,
        models.MoodEntry.created_at >= since
    ).order_by(models.MoodEntry.created_at.desc()).all()
    return entries


@router.post("/advice", response_model=schemas.MoodAdviceResponse)
async def get_mood_advice(
        req: schemas.MoodAdviceRequest,
        current_user: models.User = Depends(get_current_user)
):
    """
    Принимает комментарий пользователя (о проблеме или настроении),
    отправляет в AI и возвращает персонализированный совет.
    Минимальная длина комментария – 10 символов.
    """
    if len(req.comment.strip()) < 10:
        raise HTTPException(
            status_code=400,
            detail="Пожалуйста, опишите проблему подробнее (не менее 10 символов)."
        )

    prompt = f"""Ты — эмпатичный помощник по улучшению эмоционального состояния. Пользователь написал: "{req.comment}". 
Дай добрый, короткий и практичный совет, как справиться с этой ситуацией или улучшить настроение. Не ставь медицинских диагнозов. Если комментарий неясен, вежливо попроси уточнить. Ответ напиши на русском языке, дружелюбно и поддерживающе."""

    try:
        advice = await asyncio.to_thread(ask_support, prompt)
        return schemas.MoodAdviceResponse(advice=advice)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Не удалось получить совет. Попробуйте позже.")