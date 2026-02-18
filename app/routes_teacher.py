from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional

from . import models, schemas
from .auth import get_current_teacher_user
from .database import get_db
from .utils import generative_invite_code

router = APIRouter(prefix="/teacher", tags=["teacher"])


@router.post("/groups", response_model=schemas.GroupOut)
async def create_group(
        group_data: schemas.GroupCreate,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    """Создаёт новый класс и генерирует код приглашения."""
    while True:
        code = generative_invite_code()
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

    group_dict = {c.name: getattr(group, c.name) for c in group.__table__.columns}
    group_dict["members_count"] = 0
    return group_dict


@router.get("/groups", response_model=list[schemas.GroupOut])
async def get_my_groups(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
    groups = db.query(models.Group).filter(models.Group.teacher_id == current_user.id).all()
    result = []
    for g in groups:
        members_count = db.query(models.GroupMember).filter(models.GroupMember.group_id == g.id).count()
        group_dict = {c.name: getattr(g, c.name) for c in g.__table__.columns}
        group_dict["members_count"] = members_count
        result.append(group_dict)
    return result


@router.get("/groups/{group_id}/members", response_model=list[schemas.GroupMemberOut])
async def get_group_members(
        group_id: int,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
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


@router.patch("/groups/{group_id}/deactivate")
async def deactivate_group(
        group_id: int,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_teacher_user)
):
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
    group = db.query(models.Group).filter(
        models.Group.id == group_id,
        models.Group.teacher_id == current_user.id
    ).first()
    if not group:
        raise HTTPException(status_code=404, detail="Группа не найдена")

    while True:
        new_code = generative_invite_code()
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
    и которые ещё не подтверждены.
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
            "subject": lesson.subject.name,
            "student_name": lesson.user.username,
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