"""
Модуль маршрутов для учителей.
Позволяет создавать классы (группы), управлять кодами приглашения,
просматривать учеников и неподтверждённые уроки с вложениями.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, List

from . import models, schemas
from .auth import get_current_teacher_user
from .database import get_db
from .utils import generate_invite_code


router = APIRouter(prefix="/teacher", tags=["teacher"])


@router.post("/groups", response_model=schemas.GroupOut)
async def create_group(
        group_data: schemas.GroupCreate,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Создаёт новый класс (группу) и генерирует уникальный код приглашения.
    Можно указать срок действия кода (expires_in_days).
    """
    while True:
        code = generate_invite_code()
        existing = db.query(models.Group).filter(models.Group.invite_code == code).first()
        if not existing:
            break

    expires_at = None
    if group_data.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=group_data.expires_in_days)

    group = models.Group(
        name=group_data.name,
        school=group_data.school,
        teacher_id=current_user.id,
        invite_code=code,
        expires_at=expires_at,
        is_active=True
    )
    db.add(group)
    db.commit()
    db.refresh(group)

    # Создаем словарь для ответа
    group_dict = {
        "id": group.id,
        "name": group.name,
        "school": group.school,
        "invite_code": group.invite_code,
        "expires_at": group.expires_at,
        "is_active": group.is_active,
        "created_at": group.created_at,
        "members_count": 0
    }
    return group_dict


@router.get("/groups", response_model=List[schemas.GroupOut])
async def get_my_groups(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Возвращает список классов, созданных текущим учителем,
    с количеством участников в каждом.
    """
    groups = db.query(models.Group).filter(models.Group.teacher_id == current_user.id).all()
    result = []
    for g in groups:
        members_count = db.query(models.GroupMember).filter(models.GroupMember.group_id == g.id).count()
        group_dict = {
            "id": g.id,
            "name": g.name,
            "school": g.school,
            "invite_code": g.invite_code,
            "expires_at": g.expires_at,
            "is_active": g.is_active,
            "created_at": g.created_at,
            "members_count": members_count
        }
        result.append(group_dict)
    return result


@router.get("/groups/{group_id}/members", response_model=List[schemas.GroupMemberOut])
async def get_group_members(
        group_id: int,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Возвращает список участников конкретного класса (группы).
    Доступно только учителю, создавшему группу.
    """
    group = db.query(models.Group).filter(
        models.Group.id == group_id,
        models.Group.teacher_id == current_user.id
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Группа не найдена")

    members = db.query(models.GroupMember).filter(models.GroupMember.group_id == group_id).all()
    result = []
    for m in members:
        user = m.user
        result.append({
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "school": user.school,
            "grade": user.grade,
            "joined_at": m.joined_at
        })
    return result


@router.get("/students", response_model=List[dict])
async def get_my_students(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Возвращает список всех учеников учителя.
    """
    students = db.query(models.User).filter(
        models.User.teacher_id == current_user.id,
        models.User.is_teacher == False
    ).all()

    result = []
    for student in students:
        # Получаем группы ученика
        memberships = db.query(models.GroupMember).filter(
            models.GroupMember.user_id == student.id
        ).all()
        groups = []
        for m in memberships:
            groups.append({
                "id": m.group.id,
                "name": m.group.name
            })

        result.append({
            "id": student.id,
            "username": student.username,
            "email": student.email,
            "school": student.school,
            "grade": student.grade,
            "groups": groups
        })

    return result


@router.get("/student/{student_id}/grades")
async def get_student_grades(
        student_id: int,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Возвращает все оценки ученика.
    """
    student = db.query(models.User).filter(
        models.User.id == student_id,
        models.User.teacher_id == current_user.id,
        models.User.is_teacher == False
    ).first()

    if not student:
        raise HTTPException(status_code=404, detail="Ученик не найден")

    grades = db.query(models.Grade).filter(
        models.Grade.user_id == student_id
    ).order_by(models.Grade.date.desc()).all()

    result = []
    for grade in grades:
        result.append({
            "id": grade.id,
            "value": grade.value,
            "weight": grade.weight,
            "date": grade.date.isoformat(),
            "description": grade.description,
            "subject": grade.subject.name if grade.subject else "Неизвестно",
            "lesson_id": grade.lesson_id
        })

    return result


@router.get("/student/{student_id}/averages")
async def get_student_averages(
        student_id: int,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Возвращает средние оценки ученика по предметам.
    """
    student = db.query(models.User).filter(
        models.User.id == student_id,
        models.User.teacher_id == current_user.id,
        models.User.is_teacher == False
    ).first()

    if not student:
        raise HTTPException(status_code=404, detail="Ученик не найден")

    subjects = db.query(models.Subject).all()
    result = []

    for subject in subjects:
        grades = db.query(models.Grade).filter(
            models.Grade.user_id == student_id,
            models.Grade.subject_id == subject.id
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


@router.patch("/groups/{group_id}/deactivate")
async def deactivate_group(
        group_id: int,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Деактивирует код приглашения для группы (делает is_active=False).
    """
    group = db.query(models.Group).filter(
        models.Group.id == group_id,
        models.Group.teacher_id == current_user.id
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Группа не найдена")

    group.is_active = False
    db.commit()
    return {"success": True, "message": "Код деактивирован"}


@router.post("/groups/{group_id}/regenerate-code")
async def regenerate_code(
        group_id: int,
        expires_in_days: Optional[int] = 30,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Генерирует новый код приглашения для группы, заменяя старый.
    Можно задать новый срок действия.
    """
    group = db.query(models.Group).filter(
        models.Group.id == group_id,
        models.Group.teacher_id == current_user.id
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Группа не найдена")

    while True:
        new_code = generate_invite_code()
        existing = db.query(models.Group).filter(models.Group.invite_code == new_code).first()
        if not existing:
            break

    group.invite_code = new_code
    if expires_in_days:
        group.expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
    else:
        group.expires_at = None
    group.is_active = True
    db.commit()

    return {
        "invite_code": group.invite_code,
        "expires_at": group.expires_at,
        "is_active": group.is_active
    }


@router.get("/pending-lessons")
async def get_pending_lessons(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """
    Возвращает уроки учеников текущего учителя, у которых есть вложения
    и которые ещё не подтверждены (teacher_confirmed=False).
    """
    lessons = db.query(models.Lesson).join(
        models.User, models.Lesson.user_id == models.User.id
    ).filter(
        models.User.teacher_id == current_user.id,
        models.Lesson.teacher_confirmed == False,
        models.Lesson.attachments.any()
    ).order_by(models.Lesson.date.desc()).all()

    result = []
    for lesson in lessons:
        result.append({
            "lesson_id": lesson.id,
            "date": lesson.date.isoformat(),
            "subject": lesson.subject.name if lesson.subject else "Неизвестно",
            "student_name": lesson.user.username if lesson.user else "Неизвестно",
            "homework": lesson.homework,
            "attachments": [
                {
                    "id": att.id,
                    "file_path": att.file_path,
                    "original_filename": att.original_filename
                } for att in lesson.attachments
            ]
        })
    return result