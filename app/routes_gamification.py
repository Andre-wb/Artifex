"""
Модуль маршрутов для геймификации.
Содержит эндпоинты для получения профиля, достижений, отметки выполнения уроков,
подтверждения учителем и таблицы лидеров.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import List, Optional

from .database import get_db
from .auth import get_current_user, get_current_admin_user
from .models import User, Lesson, Achievement, UserAchievement
from . import gamification
from .schemas import (
    GamificationProfileOut,
    AchievementOut,
    AchievementWithEarnedOut,
    UserAchievementOut,
    LeaderboardEntryOut
)
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gamification", tags=["Геймификация"])

def get_user_achievements_with_status(user_id: int, db: Session) -> List[AchievementWithEarnedOut]:
    """
    Возвращает список всех достижений с флагом earned для указанного пользователя.
    """
    all_ach = db.query(Achievement).all()
    earned_ids = {ua.achievement_id for ua in db.query(UserAchievement).filter_by(user_id=user_id).all()}
    result = []
    for ach in all_ach:
        result.append(AchievementWithEarnedOut(
            id=ach.id,
            name=ach.name,
            description=ach.description,
            condition_type=ach.condition_type,
            condition_value=ach.condition_value,
            icon=ach.icon,
            earned=ach.id in earned_ids,
            earned_at=next((ua.earned_at for ua in ach.users if ua.user_id == user_id), None)
        ))
    return result


def get_recent_achievements(user_id: int, db: Session, limit: int = 5) -> List[UserAchievementOut]:
    """
    Возвращает последние полученные пользователем достижения.
    """
    recent = db.query(UserAchievement).filter_by(user_id=user_id).order_by(
        desc(UserAchievement.earned_at)
    ).limit(limit).all()
    return [
        UserAchievementOut(
            id=ua.id,
            achievement_id=ua.achievement_id,
            achievement_name=ua.achievement.name,
            achievement_description=ua.achievement.description,
            achievement_icon=ua.achievement.icon,
            earned_at=ua.earned_at
        ) for ua in recent
    ]

@router.get("/profile", response_model=GamificationProfileOut)
async def get_gamification_profile(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает игровой профиль пользователя: XP, уровень, лигу, streak,
    а также последние полученные достижения.
    """
    recent_ach = get_recent_achievements(current_user.id, db)
    return GamificationProfileOut(
        xp=current_user.xp,
        level=current_user.level,
        league=current_user.league,
        streak_days=current_user.streak_days,
        recent_achievements=recent_ach
    )


@router.get("/achievements", response_model=List[AchievementWithEarnedOut])
async def get_achievements(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает список всех доступных достижений с указанием, получены ли они текущим пользователем.
    """
    return get_user_achievements_with_status(current_user.id, db)


@router.post("/lessons/{lesson_id}/complete")
async def complete_lesson(
        lesson_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Отмечает урок как выполненный учеником.
    Требуется, чтобы урок принадлежал текущему пользователю.
    Начисляет XP за выполнение домашнего задания.
    """
    lesson = db.query(Lesson).filter(Lesson.id == lesson_id, Lesson.user_id == current_user.id).first()
    if not lesson:
        raise HTTPException(status_code=404, detail="Урок не найден или не принадлежит вам")

    if lesson.student_completed:
        raise HTTPException(status_code=400, detail="Урок уже отмечен как выполненный")

    lesson.student_completed = True
    lesson.student_completed_at = datetime.utcnow()
    db.commit()

    gamification.award_xp_for_homework_completed(current_user, datetime.utcnow(), db)

    gamification.check_achievements(current_user, db)

    return JSONResponse({"success": True, "message": "Урок отмечен выполненным"})


@router.post("/lessons/{lesson_id}/confirm")
async def confirm_lesson(
        lesson_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Подтверждает выполнение урока учителем.
    Доступно только администраторам (учителям).
    Начисляет дополнительный XP и обновляет ударный режим.
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Требуются права учителя")

    lesson = db.query(Lesson).filter(Lesson.id == lesson_id).first()
    if not lesson:
        raise HTTPException(status_code=404, detail="Урок не найден")

    if not lesson.student_completed:
        raise HTTPException(status_code=400, detail="Урок ещё не отмечен учеником как выполненный")

    if lesson.teacher_confirmed:
        raise HTTPException(status_code=400, detail="Урок уже подтверждён учителем")

    lesson.teacher_confirmed = True
    lesson.teacher_confirmed_at = datetime.utcnow()
    db.commit()

    gamification.award_xp_for_teacher_confirmation(lesson.user, db)

    gamification.check_achievements(lesson.user, db)

    return JSONResponse({"success": True, "message": "Урок подтверждён учителем"})


@router.get("/leaderboard", response_model=List[LeaderboardEntryOut])
async def get_leaderboard(
        limit: int = Query(10, ge=1, le=100),
        league: Optional[str] = Query(None, description="Фильтр по лиге (Bronze, Silver, ...)"),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает таблицу лидеров пользователей по XP.
    Можно фильтровать по лиге.
    """
    query = db.query(User).filter(User.confirmed == True)
    if league:
        if league not in gamification.LEAGUE_THRESHOLDS:
            raise HTTPException(status_code=400, detail="Неизвестная лига")
        query = query.filter(User.league == league)

    top_users = query.order_by(desc(User.xp)).limit(limit).all()

    result = []
    for u in top_users:
        result.append(LeaderboardEntryOut(
            user_id=u.id,
            username=u.username,
            xp=u.xp,
            level=u.level,
            league=u.league
        ))
    return result


@router.get("/my-achievements", response_model=List[UserAchievementOut])
async def get_my_achievements(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает только полученные пользователем достижения.
    """
    uas = db.query(UserAchievement).filter_by(user_id=current_user.id).order_by(
        desc(UserAchievement.earned_at)
    ).all()
    return [
        UserAchievementOut(
            id=ua.id,
            achievement_id=ua.achievement_id,
            achievement_name=ua.achievement.name,
            achievement_description=ua.achievement.description,
            achievement_icon=ua.achievement.icon,
            earned_at=ua.earned_at
        ) for ua in uas
    ]