import logging
from datetime import date, timedelta
from sqlalchemy.orm import Session
import asyncio

from .database import SessionLocal
from . import models
from .ai_funcs import ask_support

logger = logging.getLogger(__name__)

def analyze_user_load(user: models.User, db: Session) -> list:
    """
    Анализирует нагрузку пользователя на завтра.
    Если обнаружены подряд идущие сложные предметы, создаёт предупреждение с AI-советом.
    Возвращает список созданных предупреждений.
    """
    tomorrow = date.today() + timedelta(days=1)
    lessons = db.query(models.Lesson).filter(
        models.Lesson.user_id == user.id,
        models.Lesson.date == tomorrow
    ).order_by(models.Lesson.lesson_number).all()

    if not lessons:
        return []

    two_weeks_ago = date.today() - timedelta(days=14)
    mood_stats = {}

    for lesson in lessons:
        subject_id = lesson.subject_id
        moods = db.query(models.MoodEntry).filter(
            models.MoodEntry.user_id == user.id,
            models.MoodEntry.lesson.has(subject_id=subject_id),
            models.MoodEntry.created_at >= two_weeks_ago
        ).all()
        if moods:
            total_score = 0
            for m in moods:
                if m.mood == 'happy':
                    total_score += 1
                elif m.mood == 'neutral':
                    total_score += 2
                elif m.mood == 'sad':
                    total_score += 3
            avg_mood = total_score / len(moods)
            mood_stats[subject_id] = avg_mood

    hard_subjects = [sid for sid, avg in mood_stats.items() if avg >= 2.5]

    consecutive_hard = 0
    max_consecutive = 0
    for lesson in lessons:
        if lesson.subject_id in hard_subjects:
            consecutive_hard += 1
            max_consecutive = max(max_consecutive, consecutive_hard)
        else:
            consecutive_hard = 0

    warnings = []
    if max_consecutive >= 2:
        message = f"⚠️ Завтра у вас {max_consecutive} сложных предмета подряд. Возможно, стоит перенести что-то или подготовиться заранее."

        subjects_list = [lesson.subject.name for lesson in lessons]
        hard_list = [lesson.subject.name for lesson in lessons if lesson.subject_id in hard_subjects]

        prompt = (
            f"Ученик завтра имеет следующие уроки: {', '.join(subjects_list)}. "
            f"Из них сложными (по его прошлому опыту) являются: {', '.join(hard_list)}. "
            f"Дай дружеский, короткий и практичный совет, как справиться с высокой нагрузкой. "
            f"Ответ напиши на русском языке, без излишней формальности."
        )

        try:
            advice = ask_support(prompt, task_type="general_help")
        except Exception as e:
            logger.error(f"AI advice failed: {e}")
            advice = "Попробуйте распределить нагрузку и не забывайте отдыхать."

        existing = db.query(models.LoadWarning).filter(
            models.LoadWarning.user_id == user.id,
            models.LoadWarning.date == tomorrow,
            models.LoadWarning.is_read == False
        ).first()
        if not existing:
            warning = models.LoadWarning(
                user_id=user.id,
                message=message,
                advice=advice,
                date=tomorrow,
                is_read=False
            )
            db.add(warning)
            db.commit()
            warnings.append(warning)

    return warnings

def run_load_analysis_for_all_users(db: Session):
    """Запускает анализ для всех учеников."""
    users = db.query(models.User).filter(models.User.is_teacher == False).all()
    for user in users:
        try:
            analyze_user_load(user, db)
        except Exception as e:
            logger.error(f"Ошибка при анализе пользователя {user.id}: {e}")

async def periodic_load_analysis(interval_minutes: int = 30):
    """
    Фоновая задача, запускающая анализ нагрузки всех пользователей каждые interval_minutes минут.
    """
    while True:
        try:
            logger.info("Запуск периодического анализа нагрузки...")
            await asyncio.to_thread(run_load_analysis_sync)
            logger.info("Анализ нагрузки завершён.")
        except Exception as e:
            logger.error(f"Ошибка в периодическом анализе нагрузки: {e}", exc_info=True)
        await asyncio.sleep(interval_minutes * 60)

def run_load_analysis_sync():
    """
    Синхронная обёртка, создающая сессию БД и вызывающая run_load_analysis_for_all_users.
    """
    db = SessionLocal()
    try:
        run_load_analysis_for_all_users(db)
    finally:
        db.close()