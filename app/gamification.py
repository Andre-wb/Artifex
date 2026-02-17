"""
Модуль геймификации для дневника Artifex.
Содержит логику начисления опыта (XP), уровней, лиг, достижений и ударного режима (streak).
Ударный режим учитывает выполнение домашнего задания до 19:00 текущего дня.
"""

import logging
from datetime import datetime, date, time, timedelta
from typing import Optional, List, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from .models import User, Achievement, UserAchievement, Lesson, Grade

logger = logging.getLogger(__name__)

XP_FOR_GRADE = {
    5: 20,
    4: 15,
    3: 5,
    2: 0,
    1: 0
}
XP_FOR_HOMEWORK_COMPLETED = 10
XP_FOR_TEACHER_CONFIRM = 20
XP_FOR_LESSON_CREATED_WITH_HOMEWORK = 10

LEVEL_BASE_XP = 100

LEAGUE_THRESHOLDS = {
    "Bronze": 0,
    "Silver": 500,
    "Gold": 1500,
    "Sapphire": 3000,
    "Ruby": 5000,
    "Emerald": 7500,
    "Diamond": 10000,
    "Obsidian": 15000,
    "Legendary": 20000
}

STREAK_DEADLINE = time(19, 0)

def calculate_level(xp: int) -> int:
    """
    Вычисляет уровень пользователя на основе общего XP.
    Формула: уровень = floor(sqrt(xp / 100)) + 1
    """
    if xp < 0:
        return 1
    level = int((xp / LEVEL_BASE_XP) ** 0.5) + 1
    return max(1, level)


def get_league_for_xp(xp: int) -> str:
    """
    Определяет лигу по общему XP.
    """
    league = "Bronze"
    for name, threshold in sorted(LEAGUE_THRESHOLDS.items(), key=lambda x: x[1]):
        if xp >= threshold:
            league = name
        else:
            break
    return league


def update_league(user: User, db: Session) -> bool:
    """
    Обновляет лигу пользователя в соответствии с текущим XP.
    Возвращает True, если лига изменилась.
    """
    new_league = get_league_for_xp(user.xp)
    if new_league != user.league:
        old_league = user.league
        user.league = new_league
        logger.info(f"Пользователь {user.id} ({user.username}) перешёл из лиги {old_league} в {new_league}")
        db.commit()
        return True
    return False


def award_achievement(user: User, achievement: Achievement, db: Session) -> bool:
    """
    Выдаёт пользователю достижение, если у него его ещё нет.
    Возвращает True, если достижение было выдано.
    """
    existing = db.query(UserAchievement).filter_by(
        user_id=user.id,
        achievement_id=achievement.id
    ).first()
    if existing:
        return False

    user_ach = UserAchievement(
        user_id=user.id,
        achievement_id=achievement.id,
        earned_at=datetime.utcnow()
    )
    db.add(user_ach)
    db.commit()
    logger.info(f"Пользователь {user.id} получил достижение '{achievement.name}'")
    return True

def award_xp(user: User, amount: int, reason: str, db: Session) -> Tuple[int, int, Optional[str]]:
    """
    Начисляет пользователю XP, обновляет уровень и лигу, проверяет достижения.
    Возвращает (new_xp, new_level, new_league_if_changed) – если лига не изменилась, третье значение None.
    """
    if amount <= 0:
        return user.xp, user.level, None

    old_level = user.level
    old_league = user.league

    user.xp += amount

    new_level = calculate_level(user.xp)
    user.level = new_level

    new_league = get_league_for_xp(user.xp)
    league_changed = (new_league != old_league)
    if league_changed:
        user.league = new_league

    db.commit()

    logger.info(f"Пользователь {user.id} получил {amount} XP ({reason}). Всего XP: {user.xp}, уровень: {new_level}")

    check_achievements(user, db)

    return user.xp, new_level, new_league if league_changed else None


def check_achievements(user: User, db: Session) -> List[Achievement]:
    """
    Проверяет все доступные достижения и выдает те, условия которых выполнены.
    Возвращает список вновь полученных достижений.
    """
    newly_earned = []

    achievements = db.query(Achievement).all()
    for ach in achievements:
        if db.query(UserAchievement).filter_by(user_id=user.id, achievement_id=ach.id).first():
            continue

        earned = False

        if ach.condition_type == 'xp_total':
            if user.xp >= ach.condition_value:
                earned = True
        elif ach.condition_type == 'level':
            if user.level >= ach.condition_value:
                earned = True
        elif ach.condition_type == 'streak_days':
            if user.streak_days >= ach.condition_value:
                earned = True
        elif ach.condition_type == 'lessons_completed':
            count = db.query(Lesson).filter(
                Lesson.user_id == user.id,
                Lesson.student_completed == True
            ).count()
            if count >= ach.condition_value:
                earned = True
        elif ach.condition_type == 'teacher_confirmed':
            count = db.query(Lesson).filter(
                Lesson.user_id == user.id,
                Lesson.teacher_confirmed == True
            ).count()
            if count >= ach.condition_value:
                earned = True
        elif ach.condition_type == 'grades_without_twos':
            grades = db.query(Grade).filter(
                Grade.user_id == user.id
            ).order_by(Grade.created_at.desc()).limit(ach.condition_value).all()
            if grades and all(g.value >= 3 for g in grades):
                earned = True
        elif ach.condition_type == 'perfect_week':
            week_ago = date.today() - timedelta(days=7)
            lessons = db.query(Lesson).filter(
                Lesson.user_id == user.id,
                Lesson.date >= week_ago
            ).all()
            if lessons and all(l.teacher_confirmed for l in lessons):
                earned = True

        if earned:
            award_achievement(user, ach, db)
            newly_earned.append(ach)

    return newly_earned


def update_streak(user: User, completed_at: datetime, db: Session) -> bool:
    """
    Обновляет ударный режим (streak) после отметки о выполнении домашнего задания.
    Учитывается время дедлайна (19:00). Если completed_at <= дедлайн того же дня,
    streak увеличивается или начинается. Если после дедлайна, старый streak сбрасывается
    и начинается новый с 1 (с сегодняшним днём).

    Аргументы:
        user: объект пользователя
        completed_at: дата и время отметки выполнения
        db: сессия БД

    Возвращает:
        True, если streak был изменён (увеличен, сброшен или начат)
    """
    today = completed_at.date()
    deadline_datetime = datetime.combine(today, STREAK_DEADLINE)

    if completed_at <= deadline_datetime:
        if user.last_streak_date is None:
            user.streak_days = 1
            user.last_streak_date = today
            logger.info(f"Пользователь {user.id} начал ударный режим (вовремя)")
            db.commit()
            return True
        elif user.last_streak_date == today:
            return False
        elif user.last_streak_date == today - timedelta(days=1):
            user.streak_days += 1
            user.last_streak_date = today
            logger.info(f"Пользователь {user.id} продолжил ударный режим: {user.streak_days} дней (вовремя)")
            db.commit()
            return True
        else:
            user.streak_days = 1
            user.last_streak_date = today
            logger.info(f"Пользователь {user.id} начал новую серию (был пропуск, сейчас вовремя)")
            db.commit()
            return True
    else:
        user.streak_days = 1
        user.last_streak_date = today
        logger.info(f"Пользователь {user.id} выполнил после дедлайна. Streak сброшен и начат заново (1 день)")
        db.commit()
        return True

def award_xp_for_grade(user: User, grade_value: int, db: Session):
    """Начисляет XP за полученную оценку."""
    xp = XP_FOR_GRADE.get(grade_value, 0)
    if xp > 0:
        award_xp(user, xp, f"оценка {grade_value}", db)


def award_xp_for_homework_completed(user: User, completed_at: datetime, db: Session):
    """
    Начисляет XP за отметку о выполнении домашнего задания (учеником).
    Также обновляет ударный режим с учётом времени выполнения.
    """
    award_xp(user, XP_FOR_HOMEWORK_COMPLETED, "домашнее задание выполнено", db)
    update_streak(user, completed_at, db)


def award_xp_for_teacher_confirmation(user: User, db: Session):
    """Начисляет XP за подтверждение учителем (без влияния на streak)."""
    award_xp(user, XP_FOR_TEACHER_CONFIRM, "подтверждение учителя", db)


def award_xp_for_lesson_created_with_homework(user: User, db: Session):
    """Начисляет XP за создание урока с домашним заданием."""
    award_xp(user, XP_FOR_LESSON_CREATED_WITH_HOMEWORK, "создан урок с ДЗ", db)