"""
Модуль маршрутов для основного функционала дневника.
Ученик может самостоятельно добавлять оценки, предметы и домашние задания.
"""

from fastapi import APIRouter, Request, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import and_, func
from datetime import date, timedelta, datetime
from typing import Optional, List
import calendar

from .database import get_db
from .models import User, Subject, Lesson, Grade, TimetableTemplate
from .auth import get_current_user
from .schemas import (
    SubjectCreate, SubjectResponse,
    LessonCreate, LessonUpdate, LessonResponse,
    GradeCreate, GradeUpdate, GradeResponse,
    SubjectAverage, DayStats,
    TimetableTemplateCreate, TimetableTemplateResponse
)

router = APIRouter(prefix="/diary", tags=["diary"])
templates = Jinja2Templates(directory="templates")


def generate_lessons_from_template(db: Session, user_id: int, start_date: date, end_date: date):
    """
    Вспомогательная функция для автоматического создания уроков на основе шаблона расписания.
    """
    templates = db.query(TimetableTemplate).filter(
        TimetableTemplate.user_id == user_id
    ).all()

    if not templates:
        return

    current_date = start_date
    while current_date <= end_date:
        existing_lessons = db.query(Lesson).filter(
            Lesson.user_id == user_id,
            Lesson.date == current_date
        ).count()

        if existing_lessons == 0:
            day_templates = [t for t in templates if t.day_of_week == current_date.weekday()]
            for template in day_templates:
                lesson = Lesson(
                    user_id=user_id,
                    subject_id=template.subject_id,
                    date=current_date,
                    lesson_number=template.lesson_number,
                    start_time=template.start_time,
                    end_time=template.end_time,
                    room=template.room
                )
                db.add(lesson)

        current_date += timedelta(days=1)

    db.commit()


# ==================== HTML страницы ====================
@router.get("/", response_class=HTMLResponse)
async def diary_page(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Отображает основную страницу дневника.
    """
    today = date.today()
    end_date = today + timedelta(days=14)
    generate_lessons_from_template(db, current_user.id, today, end_date)

    days = []
    for i in range(-7, 21):
        day_date = today + timedelta(days=i)
        lessons = db.query(Lesson).filter(
            Lesson.user_id == current_user.id,
            Lesson.date == day_date
        ).order_by(Lesson.lesson_number).all()

        # Загружаем оценки для каждого урока
        lesson_ids = [lesson.id for lesson in lessons]
        if lesson_ids:
            grades = db.query(Grade).filter(Grade.lesson_id.in_(lesson_ids)).all()
            grades_by_lesson = {}
            for grade in grades:
                if grade.lesson_id not in grades_by_lesson:
                    grades_by_lesson[grade.lesson_id] = []
                grades_by_lesson[grade.lesson_id].append(grade)

            for lesson in lessons:
                lesson.grades = grades_by_lesson.get(lesson.id, [])
        else:
            for lesson in lessons:
                lesson.grades = []

        days.append({
            'date': day_date,
            'weekday': ['Пн','Вт','Ср','Чт','Пт','Сб','Вс'][day_date.weekday()],
            'lessons': lessons
        })

    subjects = db.query(Subject).all()

    return templates.TemplateResponse(
        "diary.html",
        {
            "request": request,
            "user": current_user,
            "days": days,
            "today": today,
            "subjects": subjects,
            "weekdays": ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс']
        }
    )


# ==================== API для предметов (доступно всем) ====================
@router.get("/api/subjects", response_model=List[SubjectResponse])
async def get_subjects(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Возвращает список всех предметов."""
    return db.query(Subject).all()


@router.post("/api/subjects", response_model=SubjectResponse)
async def create_subject(
        subject: SubjectCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Создаёт новый предмет (доступно всем пользователям)."""
    db_subject = Subject(**subject.dict())
    db.add(db_subject)
    db.commit()
    db.refresh(db_subject)
    return db_subject


@router.put("/api/subjects/{subject_id}", response_model=SubjectResponse)
async def update_subject(
        subject_id: int,
        subject_update: SubjectCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Обновляет существующий предмет."""
    subject = db.query(Subject).filter(Subject.id == subject_id).first()
    if not subject:
        raise HTTPException(status_code=404, detail="Предмет не найден")

    for key, value in subject_update.dict().items():
        setattr(subject, key, value)

    db.commit()
    db.refresh(subject)
    return subject


@router.delete("/api/subjects/{subject_id}")
async def delete_subject(
        subject_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Удаляет предмет, если к нему не привязаны уроки."""
    subject = db.query(Subject).filter(Subject.id == subject_id).first()
    if not subject:
        raise HTTPException(status_code=404, detail="Предмет не найден")

    lessons_count = db.query(Lesson).filter(Lesson.subject_id == subject_id).count()
    if lessons_count > 0:
        raise HTTPException(status_code=400, detail="Нельзя удалить предмет с существующими уроками")

    db.delete(subject)
    db.commit()
    return {"ok": True}


# ==================== API для уроков (доступно всем) ====================
@router.get("/api/lessons", response_model=List[LessonResponse])
async def get_lessons(
        date_from: Optional[date] = None,
        date_to: Optional[date] = None,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Возвращает список уроков текущего пользователя."""
    query = db.query(Lesson).filter(Lesson.user_id == current_user.id)

    if date_from:
        query = query.filter(Lesson.date >= date_from)
    if date_to:
        query = query.filter(Lesson.date <= date_to)

    lessons = query.order_by(Lesson.date, Lesson.lesson_number).all()

    # Загружаем оценки для каждого урока
    lesson_ids = [lesson.id for lesson in lessons]
    if lesson_ids:
        grades = db.query(Grade).filter(Grade.lesson_id.in_(lesson_ids)).all()
        grades_by_lesson = {}
        for grade in grades:
            if grade.lesson_id not in grades_by_lesson:
                grades_by_lesson[grade.lesson_id] = []
            grades_by_lesson[grade.lesson_id].append(grade)

        for lesson in lessons:
            lesson.grades = grades_by_lesson.get(lesson.id, [])
    else:
        for lesson in lessons:
            lesson.grades = []

    return lessons


@router.get("/api/lessons/{lesson_id}", response_model=LessonResponse)
async def get_lesson(
        lesson_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Возвращает детальную информацию об уроке."""
    lesson = db.query(Lesson).filter(
        Lesson.id == lesson_id,
        Lesson.user_id == current_user.id
    ).first()
    if not lesson:
        raise HTTPException(status_code=404, detail="Урок не найден")

    lesson.grades = db.query(Grade).filter(Grade.lesson_id == lesson.id).all()
    return lesson


@router.post("/api/lessons", response_model=LessonResponse)
async def create_lesson(
        lesson: LessonCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Создаёт новый урок для текущего пользователя."""
    db_lesson = Lesson(**lesson.dict(), user_id=current_user.id)
    db.add(db_lesson)
    db.commit()
    db.refresh(db_lesson)
    db_lesson.grades = []
    return db_lesson


@router.put("/api/lessons/{lesson_id}", response_model=LessonResponse)
async def update_lesson(
        lesson_id: int,
        lesson_update: LessonUpdate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Обновляет существующий урок."""
    db_lesson = db.query(Lesson).filter(
        Lesson.id == lesson_id,
        Lesson.user_id == current_user.id
    ).first()
    if not db_lesson:
        raise HTTPException(status_code=404, detail="Урок не найден")

    for key, value in lesson_update.dict(exclude_unset=True).items():
        setattr(db_lesson, key, value)

    db.commit()
    db.refresh(db_lesson)
    db_lesson.grades = db.query(Grade).filter(Grade.lesson_id == db_lesson.id).all()
    return db_lesson


@router.delete("/api/lessons/{lesson_id}")
async def delete_lesson(
        lesson_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Удаляет урок."""
    db_lesson = db.query(Lesson).filter(
        Lesson.id == lesson_id,
        Lesson.user_id == current_user.id
    ).first()
    if not db_lesson:
        raise HTTPException(status_code=404, detail="Урок не найден")

    db.delete(db_lesson)
    db.commit()
    return {"ok": True}


# ==================== API для оценок (доступно всем) ====================
@router.get("/api/grades", response_model=List[GradeResponse])
async def get_grades(
        subject_id: Optional[int] = None,
        date_from: Optional[date] = None,
        date_to: Optional[date] = None,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Возвращает список оценок текущего пользователя."""
    query = db.query(Grade).filter(Grade.user_id == current_user.id)

    if subject_id:
        query = query.filter(Grade.subject_id == subject_id)
    if date_from:
        query = query.filter(Grade.date >= date_from)
    if date_to:
        query = query.filter(Grade.date <= date_to)

    grades = query.order_by(Grade.date.desc()).all()

    # Загружаем связанные данные
    for grade in grades:
        grade.subject = db.query(Subject).filter(Subject.id == grade.subject_id).first()
        if grade.lesson_id:
            grade.lesson = db.query(Lesson).filter(Lesson.id == grade.lesson_id).first()

    return grades


@router.get("/api/grades/{grade_id}", response_model=GradeResponse)
async def get_grade(
        grade_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Возвращает оценку по ID."""
    grade = db.query(Grade).filter(
        Grade.id == grade_id,
        Grade.user_id == current_user.id
    ).first()
    if not grade:
        raise HTTPException(status_code=404, detail="Оценка не найдена")

    grade.subject = db.query(Subject).filter(Subject.id == grade.subject_id).first()
    if grade.lesson_id:
        grade.lesson = db.query(Lesson).filter(Lesson.id == grade.lesson_id).first()

    return grade


@router.post("/api/grades", response_model=GradeResponse)
async def create_grade(
        grade: GradeCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Создаёт оценку для текущего пользователя."""
    # Проверяем существование предмета
    subject = db.query(Subject).filter(Subject.id == grade.subject_id).first()
    if not subject:
        raise HTTPException(status_code=404, detail="Предмет не найден")

    # Проверяем урок, если указан
    if grade.lesson_id:
        lesson = db.query(Lesson).filter(
            Lesson.id == grade.lesson_id,
            Lesson.user_id == current_user.id
        ).first()
        if not lesson:
            raise HTTPException(status_code=404, detail="Урок не найден")

    db_grade = Grade(
        user_id=current_user.id,
        subject_id=grade.subject_id,
        lesson_id=grade.lesson_id,
        value=grade.value,
        weight=grade.weight,
        date=grade.date,
        description=grade.description
    )
    db.add(db_grade)
    db.commit()
    db.refresh(db_grade)

    db_grade.subject = subject
    if grade.lesson_id:
        db_grade.lesson = lesson

    return db_grade


@router.put("/api/grades/{grade_id}", response_model=GradeResponse)
async def update_grade(
        grade_id: int,
        grade_update: GradeUpdate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Обновляет существующую оценку."""
    db_grade = db.query(Grade).filter(
        Grade.id == grade_id,
        Grade.user_id == current_user.id
    ).first()
    if not db_grade:
        raise HTTPException(status_code=404, detail="Оценка не найдена")

    for key, value in grade_update.dict(exclude_unset=True).items():
        setattr(db_grade, key, value)

    db.commit()
    db.refresh(db_grade)

    db_grade.subject = db.query(Subject).filter(Subject.id == db_grade.subject_id).first()
    if db_grade.lesson_id:
        db_grade.lesson = db.query(Lesson).filter(Lesson.id == db_grade.lesson_id).first()

    return db_grade


@router.delete("/api/grades/{grade_id}")
async def delete_grade(
        grade_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Удаляет оценку."""
    db_grade = db.query(Grade).filter(
        Grade.id == grade_id,
        Grade.user_id == current_user.id
    ).first()
    if not db_grade:
        raise HTTPException(status_code=404, detail="Оценка не найдена")

    db.delete(db_grade)
    db.commit()
    return {"ok": True}


# ==================== API для статистики ====================
@router.get("/api/stats/averages")
async def get_averages(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Возвращает средние оценки по каждому предмету."""
    subjects = db.query(Subject).all()
    result = []

    for subject in subjects:
        grades = db.query(Grade).filter(
            Grade.user_id == current_user.id,
            Grade.subject_id == subject.id
        ).all()

        if grades:
            total_weight = sum(g.weight for g in grades)
            weighted_sum = sum(g.value * g.weight for g in grades)
            average = weighted_sum / total_weight if total_weight > 0 else 0
        else:
            average = 0

        result.append({
            "subject_id": subject.id,
            "subject_name": subject.name,
            "average": round(average, 2),
            "grades_count": len(grades),
            "color": getattr(subject, 'color', '#667eea')
        })

    return result


# ==================== API для шаблона расписания ====================
@router.get("/api/timetable-template", response_model=List[TimetableTemplateResponse])
async def get_timetable_template(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Возвращает шаблон расписания."""
    return db.query(TimetableTemplate).filter(
        TimetableTemplate.user_id == current_user.id
    ).order_by(TimetableTemplate.day_of_week, TimetableTemplate.lesson_number).all()


@router.post("/api/timetable-template", response_model=TimetableTemplateResponse)
async def create_timetable_template(
        template: TimetableTemplateCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Создаёт или обновляет запись в шаблоне расписания."""
    existing = db.query(TimetableTemplate).filter(
        TimetableTemplate.user_id == current_user.id,
        TimetableTemplate.day_of_week == template.day_of_week,
        TimetableTemplate.lesson_number == template.lesson_number
    ).first()

    if existing:
        for key, value in template.dict().items():
            setattr(existing, key, value)
        db.commit()
        db.refresh(existing)
        return existing
    else:
        db_template = TimetableTemplate(**template.dict(), user_id=current_user.id)
        db.add(db_template)
        db.commit()
        db.refresh(db_template)
        return db_template


@router.delete("/api/timetable-template/{template_id}")
async def delete_timetable_template(
        template_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Удаляет запись из шаблона расписания."""
    db_template = db.query(TimetableTemplate).filter(
        TimetableTemplate.id == template_id,
        TimetableTemplate.user_id == current_user.id
    ).first()
    if not db_template:
        raise HTTPException(status_code=404, detail="Запись не найдена")

    db.delete(db_template)
    db.commit()
    return {"ok": True}


@router.post("/api/generate-lessons")
async def generate_lessons(
        weeks_ahead: int = 2,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """Ручной запуск генерации уроков из шаблона."""
    today = date.today()
    end_date = today + timedelta(days=weeks_ahead * 7)
    generate_lessons_from_template(db, current_user.id, today, end_date)
    return {"ok": True, "message": f"Уроки созданы до {end_date}"}