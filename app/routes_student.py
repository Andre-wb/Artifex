"""
Модуль маршрутов для учеников.
Содержит эндпоинты для присоединения к классу по коду и просмотра своих классов.
"""

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime

from . import models, schemas
from .config import Config
from .database import get_db
from .auth import get_current_user

router = APIRouter()

is_production = Config.ENVIRONMENT == 'production' if hasattr(Config, 'ENVIRONMENT') else False


@router.post("/user/join-group")
async def join_group(
        request: Request,
        join_data: schemas.GroupJoinRequest,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Присоединение ученика к классу (группе) по коду приглашения.
    Если у пользователя ещё не заполнены школа и класс, они заполняются из группы.
    """
    group = db.query(models.Group).filter(
        models.Group.invite_code == join_data.invite_code,
        models.Group.is_active == True
    ).first()

    if not group:
        raise HTTPException(status_code=400, detail="Неверный или неактивный код приглашения")

    if group.expires_at and group.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Срок действия кода истёк")

    existing = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group.id,
        models.GroupMember.user_id == current_user.id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Вы уже состоите в этом классе")

    member = models.GroupMember(group_id=group.id, user_id=current_user.id)
    db.add(member)

    # Если у ученика нет школы/класса, заполняем из группы
    if not current_user.school:
        current_user.school = group.school
    if not current_user.grade:
        current_user.grade = group.name

    db.commit()

    return {
        "success": True,
        "group": {
            "id": group.id,
            "name": group.name,
            "school": group.school,
            "teacher": group.teacher.username if group.teacher else None
        }
    }


@router.get("/user/my-groups")
async def get_my_groups(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Возвращает список классов (групп), в которых состоит ученик.
    """
    memberships = db.query(models.GroupMember).filter(
        models.GroupMember.user_id == current_user.id
    ).all()

    result = []
    for m in memberships:
        group = m.group
        result.append({
            "id": group.id,
            "name": group.name,
            "school": group.school,
            "teacher": group.teacher.username if group.teacher else None,
            "joined_at": m.joined_at
        })
    return result