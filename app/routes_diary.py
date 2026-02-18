"""
Модуль маршрутов для основного функционала дневника.
Включает:
- отображение страницы дневника (HTML)
- API для управления предметами, уроками, оценками
- API для статистики и шаблонов расписания
"""

from fastapi import APIRouter, Request, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import and_, func
from datetime import date, timedelta, datetime
from typing import Optional, List
import calendar
from .auth import get_current_user, get_current_user_optional

from .database import get_db
from .models import User, Subject, Lesson, Grade, TimetableTemplate
from .auth import get_current_user, get_current_teacher_user
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
    Создаёт уроки на каждый день в указанном диапазоне, если их ещё нет.
    """
    templates = db.query(TimetableTemplate).filter(
        TimetableTemplate.user_id == user_id
    ).all()

    if not templates:
        return

    current_date = start_date
    while current_date <= end_date:
        # Проверяем, есть ли уже уроки в этот день
        existing_lessons = db.query(Lesson).filter(
            Lesson.user_id == user_id,
            Lesson.date == current_date
        ).count()

        # Если уроков нет, создаём из шаблона
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
    Отображает основную страницу дневника с расписанием на ближайшие дни.
    Автоматически генерирует уроки на 2 недели вперёд, если их нет.
    """
    today = date.today()

    # Автоматически создаем уроки на 2 недели вперед
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
        for lesson in lessons:
            lesson.grades = db.query(Grade).filter(
                Grade.lesson_id == lesson.id
            ).all()

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


@router.get("/stats", response_class=HTMLResponse)
async def stats_page(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Отображает страницу статистики успеваемости.
    """
    subjects = db.query(Subject).all()
    return templates.TemplateResponse(
        "stats.html",
        {
            "request": request,
            "user": current_user,
            "subjects": subjects
        }
    )


# ==================== API для предметов ====================
@router.get("/api/subjects", response_model=List[SubjectResponse])
async def get_subjects(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает список всех предметов.
    """
    return db.query(Subject).all()


@router.post("/api/subjects", response_model=SubjectResponse)
async def create_subject(
        subject: SubjectCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Создаёт новый предмет. Доступно всем аутентифицированным пользователям.
    """
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
    """
    Обновляет существующий предмет.
    """
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
    """
    Удаляет предмет, только если к нему не привязаны уроки.
    """
    subject = db.query(Subject).filter(Subject.id == subject_id).first()
    if not subject:
        raise HTTPException(status_code=404, detail="Предмет не найден")

    lessons_count = db.query(Lesson).filter(Lesson.subject_id == subject_id).count()
    if lessons_count > 0:
        raise HTTPException(status_code=400, detail="Нельзя удалить предмет с существующими уроками")

    db.delete(subject)
    db.commit()
    return {"ok": True}


# ==================== API для уроков ====================
@router.get("/api/lessons", response_model=List[LessonResponse])
async def get_lessons(
        date_from: Optional[date] = None,
        date_to: Optional[date] = None,
        user_id: Optional[int] = None,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает список уроков.
    Если user_id указан и текущий пользователь - учитель, возвращает уроки указанного ученика.
    Иначе возвращает уроки текущего пользователя.
    """
    # Если запрошены уроки другого пользователя
    if user_id and user_id != current_user.id:
        # Проверяем, имеет ли текущий пользователь право (учитель этого ученика)
        if not current_user.is_teacher:
            raise HTTPException(status_code=403, detail="Нет прав на просмотр уроков других пользователей")

        student = db.query(User).filter(
            User.id == user_id,
            User.teacher_id == current_user.id
        ).first()

        if not student:
            raise HTTPException(status_code=403, detail="Этот ученик не ваш")

        query = db.query(Lesson).filter(Lesson.user_id == user_id)
    else:
        # Свои уроки
        query = db.query(Lesson).filter(Lesson.user_id == current_user.id)

    if date_from:
        query = query.filter(Lesson.date >= date_from)
    if date_to:
        query = query.filter(Lesson.date <= date_to)

    lessons = query.order_by(Lesson.date, Lesson.lesson_number).all()

    # Загружаем оценки для каждого урока
    for lesson in lessons:
        lesson.grades = db.query(Grade).filter(Grade.lesson_id == lesson.id).all()

    return lessons


@router.get("/api/lessons/{lesson_id}", response_model=LessonResponse)
async def get_lesson(
        lesson_id: int,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает детальную информацию об уроке по его ID.
    """
    lesson = db.query(Lesson).filter(Lesson.id == lesson_id).first()
    if not lesson:
        raise HTTPException(status_code=404, detail="Урок не найден")

    # Проверка прав доступа
    if lesson.user_id != current_user.id:
        # Если это не свой урок, проверяем, является ли текущий пользователь учителем этого ученика
        if not current_user.is_teacher:
            raise HTTPException(status_code=403, detail="Нет доступа к этому уроку")

        student = db.query(User).filter(
            User.id == lesson.user_id,
            User.teacher_id == current_user.id
        ).first()

        if not student:
            raise HTTPException(status_code=403, detail="Это не ваш ученик")

    lesson.grades = db.query(Grade).filter(Grade.lesson_id == lesson.id).all()
    return lesson


@router.post("/api/lessons", response_model=LessonResponse)
async def create_lesson(
        lesson: LessonCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Создаёт новый урок для текущего пользователя.
    """
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
    """
    Обновляет существующий урок.
    """
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
    """
    Удаляет урок.
    """
    db_lesson = db.query(Lesson).filter(
        Lesson.id == lesson_id,
        Lesson.user_id == current_user.id
    ).first()
    if not db_lesson:
        raise HTTPException(status_code=404, detail="Урок не найден")

    db.delete(db_lesson)
    db.commit()
    return {"ok": True}


# ==================== API для оценок ====================
@router.get("/api/grades", response_model=List[GradeResponse])
async def get_grades(
        subject_id: Optional[int] = None,
        date_from: Optional[date] = None,
        date_to: Optional[date] = None,
        user_id: Optional[int] = None,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает список оценок.
    Если user_id указан и текущий пользователь - учитель, возвращает оценки указанного ученика.
    Иначе возвращает оценки текущего пользователя.
    """
    # Если запрошены оценки другого пользователя
    if user_id and user_id != current_user.id:
        # Проверяем, имеет ли текущий пользователь право (учитель этого ученика)
        if not current_user.is_teacher:
            raise HTTPException(status_code=403, detail="Нет прав на просмотр оценок других пользователей")

        student = db.query(User).filter(
            User.id == user_id,
            User.teacher_id == current_user.id
        ).first()

        if not student:
            raise HTTPException(status_code=403, detail="Этот ученик не ваш")

        query = db.query(Grade).filter(Grade.user_id == user_id)
    else:
        # Свои оценки
        query = db.query(Grade).filter(Grade.user_id == current_user.id)

    if subject_id:
        query = query.filter(Grade.subject_id == subject_id)
    if date_from:
        query = query.filter(Grade.date >= date_from)
    if date_to:
        query = query.filter(Grade.date <= date_to)

    return query.order_by(Grade.date.desc()).all()


@router.post("/api/grades", response_model=GradeResponse)
async def create_grade(
        grade: GradeCreate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_teacher_user)
):
    """
    Создаёт оценку для ученика (учитель может ставить оценку только своим ученикам).
    Привязывается к конкретному уроку.
    """
    # Проверяем, указан ли lesson_id
    if not grade.lesson_id:
        raise HTTPException(status_code=400, detail="Необходимо указать урок")

    lesson = db.query(Lesson).filter(Lesson.id == grade.lesson_id).first()
    if not lesson:
        raise HTTPException(status_code=404, detail="Урок не найден")

    student = db.query(User).filter(User.id == lesson.user_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Ученик не найден")

    # Проверяем, что учитель имеет право ставить оценку этому ученику
    if student.teacher_id != current_user.id:
        raise HTTPException(status_code=403, detail="Этот ученик не ваш")

    # Создаем оценку
    db_grade = Grade(
        user_id=lesson.user_id,
        subject_id=lesson.subject_id,
        lesson_id=grade.lesson_id,
        value=grade.value,
        weight=grade.weight,
        date=grade.date,
        description=grade.description
    )
    db.add(db_grade)
    db.commit()
    db.refresh(db_grade)

    # Загружаем связанные данные для ответа
    db_grade.subject = lesson.subject
    db_grade.lesson = lesson

    return db_grade

@router.put("/api/grades/{grade_id}", response_model=GradeResponse)
async def update_grade(
        grade_id: int,
        grade_update: GradeUpdate,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_teacher_user)
):
    """
    Обновляет существующую оценку. Доступно только учителю, который является учителем ученика.
    """
    db_grade = db.query(Grade).filter(Grade.id == grade_id).first()
    if not db_grade:
        raise HTTPException(status_code=404, detail="Оценка не найдена")

    lesson = db_grade.lesson
    if not lesson:
        raise HTTPException(status_code=400, detail="Оценка не привязана к уроку")

    student = db.query(User).filter(User.id == lesson.user_id).first()
    if not student or student.teacher_id != current_user.id:
        raise HTTPException(status_code=403, detail="Этот ученик не ваш")

    for key, value in grade_update.dict(exclude_unset=True).items():
        setattr(db_grade, key, value)

    db.commit()
    db.refresh(db_grade)
    return db_grade


@router.delete("/api/grades/{grade_id}")
async def delete_grade(
        grade_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_teacher_user)
):
    """
    Удаляет оценку. Доступно только учителю ученика.
    """
    db_grade = db.query(Grade).filter(Grade.id == grade_id).first()
    if not db_grade:
        raise HTTPException(status_code=404, detail="Оценка не найдена")

    lesson = db_grade.lesson
    if not lesson:
        raise HTTPException(status_code=400, detail="Оценка не привязана к уроку")

    student = db.query(User).filter(User.id == lesson.user_id).first()
    if not student or student.teacher_id != current_user.id:
        raise HTTPException(status_code=403, detail="Этот ученик не ваш")

    db.delete(db_grade)
    db.commit()
    return {"ok": True}


# ==================== API для статистики ====================
@router.get("/api/stats/averages")
async def get_averages(
        user_id: Optional[int] = None,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает средние оценки по каждому предмету (средневзвешенные).
    Если user_id указан и текущий пользователь - учитель, возвращает для указанного ученика.
    Иначе возвращает для текущего пользователя.
    """
    target_user_id = current_user.id

    # Если запрошена статистика другого пользователя
    if user_id and user_id != current_user.id:
        if not current_user.is_teacher:
            raise HTTPException(status_code=403, detail="Нет прав на просмотр статистики других пользователей")

        student = db.query(User).filter(
            User.id == user_id,
            User.teacher_id == current_user.id
        ).first()

        if not student:
            raise HTTPException(status_code=403, detail="Этот ученик не ваш")

        target_user_id = user_id

    subjects = db.query(Subject).all()
    result = []

    for subject in subjects:
        grades = db.query(Grade).filter(
            Grade.user_id == target_user_id,
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
            "color": subject.color
        })

    return result


# ==================== API для шаблона расписания ====================
@router.get("/api/timetable-template", response_model=List[TimetableTemplateResponse])
async def get_timetable_template(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Возвращает шаблон расписания для текущего пользователя.
    """
    return db.query(TimetableTemplate).filter(
        TimetableTemplate.user_id == current_user.id
    ).order_by(TimetableTemplate.day_of_week, TimetableTemplate.lesson_number).all()


@router.post("/api/timetable-template", response_model=TimetableTemplateResponse)
async def create_timetable_template(
        template: TimetableTemplateCreate,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Создаёт или обновляет запись в шаблоне расписания.
    Если для указанного дня недели и номера урока уже есть запись, она обновляется.
    """
    # Проверяем, нет ли уже такого урока в шаблоне
    existing = db.query(TimetableTemplate).filter(
        TimetableTemplate.user_id == current_user.id,
        TimetableTemplate.day_of_week == template.day_of_week,
        TimetableTemplate.lesson_number == template.lesson_number
    ).first()

    if existing:
        # Обновляем существующий
        for key, value in template.dict().items():
            setattr(existing, key, value)
        db.commit()
        db.refresh(existing)
        return existing
    else:
        # Создаем новый
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
    """
    Удаляет запись из шаблона расписания.
    """
    db_template = db.query(TimetableTemplate).filter(
        TimetableTemplate.id == template_id,
        TimetableTemplate.user_id == current_user.id
    ).first()
    if not db_template:
        raise HTTPException(status_code=404, detail="Запись не найдена")

    db.delete(db_template)
    db.commit()
    return {"ok": True}


# ==================== Ручной запуск генерации расписания ====================
@router.post("/api/generate-lessons")
async def generate_lessons(
        weeks_ahead: int = 2,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Ручной запуск генерации уроков из шаблона на указанное количество недель вперёд.
    """
    today = date.today()
    end_date = today + timedelta(days=weeks_ahead * 7)
    generate_lessons_from_template(db, current_user.id, today, end_date)
    return {"ok": True, "message": f"Уроки созданы до {end_date}"}