"""
Модуль маршрутов для управления учебными периодами (четверти, полугодия)
и итоговыми оценками. Доступ к некоторым эндпоинтам ограничен учителями.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_
from datetime import date, datetime
from typing import List, Optional

from . import models, schemas
from .auth import get_current_user, get_current_teacher_user
from .database import get_db

router = APIRouter(prefix="/academic", tags=["academic"])


@router.post("/terms", response_model=schemas.AcademicTermOut)
def create_term(
        term: schemas.AcademicTermCreate,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Создаёт новый учебный период (четверть, полугодие, год).

    - **term**: данные периода (название, тип, даты, учебный год)
    - Доступно только пользователям с ролью учителя (is_teacher=True).
    """
    db_term = models.AcademicTerm(**term.dict())
    db.add(db_term)
    db.commit()
    db.refresh(db_term)
    return db_term


@router.get("/terms", response_model=List[schemas.AcademicTermOut])
def list_terms(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Возвращает список всех учебных периодов, отсортированных по дате начала.
    Доступно всем аутентифицированным пользователям.
    """
    return db.query(models.AcademicTerm).order_by(models.AcademicTerm.start_date).all()


@router.get("/terms/current", response_model=schemas.AcademicTermOut)
def get_current_term(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Возвращает текущий учебный период (дата сегодня попадает в интервал).
    Если такого периода нет, возвращает 404.
    """
    today = date.today()
    term = db.query(models.AcademicTerm).filter(
        models.AcademicTerm.start_date <= today,
        models.AcademicTerm.end_date >= today
    ).first()
    if not term:
        raise HTTPException(status_code=404, detail="Нет активного учебного периода")
    return term


def calculate_final_grade(user_id: int, subject_id: int, term_id: int, db: Session) -> Optional[int]:
    """
    Вспомогательная функция для расчёта итоговой оценки за период
    по средневзвешенному всех оценок пользователя по предмету.

    Возвращает целое число (2-5) или None, если нет оценок.
    """
    # Получаем период, чтобы ограничить даты оценок
    term = db.query(models.AcademicTerm).filter(models.AcademicTerm.id == term_id).first()
    if not term:
        return None

    grades = db.query(models.Grade).filter(
        models.Grade.user_id == user_id,
        models.Grade.subject_id == subject_id,
        models.Grade.date >= term.start_date,
        models.Grade.date <= term.end_date
    ).all()

    if not grades:
        return None

    total_weight = sum(g.weight for g in grades)
    if total_weight == 0:
        return None

    weighted_sum = sum(g.value * g.weight for g in grades)
    average = weighted_sum / total_weight

    # Преобразование среднего балла в пятибалльную шкалу
    if average >= 4.5:
        return 5
    elif average >= 3.5:
        return 4
    elif average >= 2.5:
        return 3
    else:
        return 2


@router.post("/final/calculate")
def calculate_final_grades(
        req: schemas.TermGradeRequest,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Рассчитывает и сохраняет (или обновляет) итоговые оценки для всех учеников
    (или одного, если указан user_id) по указанному периоду и предмету (или всем).

    - **req**: содержит term_id, опционально user_id и subject_id.
    - Доступно только учителям.
    """
    term = db.query(models.AcademicTerm).filter(models.AcademicTerm.id == req.term_id).first()
    if not term:
        raise HTTPException(status_code=404, detail="Период не найден")

    users_query = db.query(models.User).filter(models.User.is_teacher == False)
    if req.user_id:
        users_query = users_query.filter(models.User.id == req.user_id)

    subjects_query = db.query(models.Subject)
    if req.subject_id:
        subjects_query = subjects_query.filter(models.Subject.id == req.subject_id)

    results = []
    for user in users_query.all():
        for subject in subjects_query.all():
            final_value = calculate_final_grade(user.id, subject.id, term.id, db)

            final_grade = db.query(models.FinalGrade).filter(
                models.FinalGrade.user_id == user.id,
                models.FinalGrade.subject_id == subject.id,
                models.FinalGrade.term_id == term.id
            ).first()

            if final_grade:
                final_grade.value = final_value
                final_grade.calculated_from = 'auto'
                final_grade.updated_at = datetime.utcnow()
            else:
                final_grade = models.FinalGrade(
                    user_id=user.id,
                    subject_id=subject.id,
                    term_id=term.id,
                    value=final_value,
                    calculated_from='auto'
                )
                db.add(final_grade)
            results.append({
                "user_id": user.id,
                "subject_id": subject.id,
                "value": final_value
            })

    db.commit()
    return {"calculated": results}


@router.get("/final/my", response_model=List[schemas.FinalGradeOut])
def get_my_final_grades(
        term_id: Optional[int] = None,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Возвращает итоговые оценки текущего пользователя (ученика).
    Если term_id указан, возвращает только за указанный период.
    """
    query = db.query(models.FinalGrade).filter(models.FinalGrade.user_id == current_user.id)
    if term_id:
        query = query.filter(models.FinalGrade.term_id == term_id)
    return query.order_by(models.FinalGrade.term_id, models.FinalGrade.subject_id).all()


@router.get("/final/student/{student_id}", response_model=List[schemas.FinalGradeOut])
def get_student_final_grades(
        student_id: int,
        term_id: Optional[int] = None,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Учитель может просмотреть итоговые оценки конкретного ученика.
    """
    student = db.query(models.User).filter(models.User.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Ученик не найден")
    query = db.query(models.FinalGrade).filter(models.FinalGrade.user_id == student_id)
    if term_id:
        query = query.filter(models.FinalGrade.term_id == term_id)
    return query.order_by(models.FinalGrade.term_id, models.FinalGrade.subject_id).all()


@router.put("/final/{final_grade_id}", response_model=schemas.FinalGradeOut)
def update_final_grade(
        final_grade_id: int,
        update: schemas.FinalGradeUpdate,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Ручная корректировка итоговой оценки учителем.
    Позволяет изменить значение и добавить комментарий.
    """
    final_grade = db.query(models.FinalGrade).filter(models.FinalGrade.id == final_grade_id).first()
    if not final_grade:
        raise HTTPException(status_code=404, detail="Итоговая оценка не найдена")

    if update.value is not None:
        final_grade.value = update.value
        final_grade.calculated_from = 'manual'
    if update.comment is not None:
        final_grade.comment = update.comment
    final_grade.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(final_grade)
    return final_grade