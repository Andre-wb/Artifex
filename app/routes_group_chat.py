"""
Модуль маршрутов для группового чата внутри классов (групп).
Позволяет получать и отправлять сообщения в группе, доступ только участникам.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from . import models, schemas
from .auth import get_current_user
from .database import get_db

router = APIRouter(prefix="/groups", tags=["group chat"])


@router.get("/{group_id}/messages")
async def get_group_messages(
        group_id: int,
        limit: int = 50,
        offset: int = 0,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Возвращает последние сообщения в группе (пагинация).
    Доступно только участникам группы.
    """
    member = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group_id,
        models.GroupMember.user_id == current_user.id
    ).first()
    if not member:
        raise HTTPException(status_code=403, detail="Вы не участник этой группы")

    messages = db.query(models.GroupMessage).filter(
        models.GroupMessage.group_id == group_id
    ).order_by(models.GroupMessage.created_at.desc()).offset(offset).limit(limit).all()

    return [
        {
            "id": msg.id,
            "user_id": msg.user_id,
            "username": msg.user.username,
            "content": msg.content,
            "created_at": msg.created_at.isoformat()
        }
        for msg in messages
    ]


@router.post("/{group_id}/messages")
async def send_group_message(
        group_id: int,
        content: str,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Отправляет сообщение в группу.
    Доступно только участникам группы.
    """
    member = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group_id,
        models.GroupMember.user_id == current_user.id
    ).first()
    if not member:
        raise HTTPException(status_code=403, detail="Вы не участник этой группы")

    if not content.strip():
        raise HTTPException(status_code=400, detail="Сообщение не может быть пустым")

    message = models.GroupMessage(
        group_id=group_id,
        user_id=current_user.id,
        content=content.strip()
    )
    db.add(message)
    db.commit()
    db.refresh(message)

    return {
        "id": message.id,
        "user_id": message.user_id,
        "username": current_user.username,
        "content": message.content,
        "created_at": message.created_at.isoformat()
    }