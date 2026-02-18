"""
Модуль маршрутов для личных сообщений (чат).
Позволяет отправлять сообщения, получать диалог, отмечать прочитанные,
получать список контактов и количество непрочитанных.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc
from typing import List

from . import models, schemas
from .auth import get_current_user
from .database import get_db

router = APIRouter(prefix="/chat", tags=["chat"])


@router.post("/send")
async def send_message(
        req: schemas.SendMessageRequest,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Отправляет личное сообщение другому пользователю.
    Проверяет, что получатель существует и что отправитель имеет право писать ему
    (ученик может писать только своему учителю, учитель – только своим ученикам).
    """
    if req.receiver_id == current_user.id:
        raise HTTPException(status_code=400, detail="Нельзя отправить сообщение самому себе")

    receiver = db.query(models.User).filter(models.User.id == req.receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Получатель не найден")

    # Проверка прав: ученик может писать только своему учителю
    if not current_user.is_teacher:
        if current_user.teacher_id != req.receiver_id:
            raise HTTPException(status_code=403, detail="Вы можете писать только своему учителю")

    # Учитель может писать только своим ученикам
    if current_user.is_teacher:
        if not receiver.is_teacher and receiver.teacher_id != current_user.id:
            raise HTTPException(status_code=403, detail="Вы можете писать только своим ученикам")

    message = models.Message(
        sender_id=current_user.id,
        receiver_id=req.receiver_id,
        content=req.content.strip()
    )
    db.add(message)
    db.commit()
    db.refresh(message)

    return {"success": True, "message_id": message.id}


@router.get("/dialog/{user_id}", response_model=List[schemas.MessageOut])
async def get_dialog(
        user_id: int,
        limit: int = 50,
        offset: int = 0,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Возвращает историю переписки с указанным пользователем (пагинация).
    Автоматически помечает входящие сообщения как прочитанные.
    Проверяет права доступа к диалогу.
    """
    other = db.query(models.User).filter(models.User.id == user_id).first()
    if not other:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    # Проверка прав
    if not current_user.is_teacher and current_user.teacher_id != user_id:
        raise HTTPException(status_code=403, detail="Вы можете читать только диалог со своим учителем")

    if current_user.is_teacher and not other.is_teacher and other.teacher_id != current_user.id:
        raise HTTPException(status_code=403, detail="Это не ваш ученик")

    messages = db.query(models.Message).filter(
        or_(
            and_(models.Message.sender_id == current_user.id, models.Message.receiver_id == user_id),
            and_(models.Message.sender_id == user_id, models.Message.receiver_id == current_user.id)
        )
    ).order_by(desc(models.Message.created_at)).offset(offset).limit(limit).all()

    # Отметка прочитанных
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
    db.commit()

    return [
        schemas.MessageOut(
            id=msg.id,
            sender_id=msg.sender_id,
            sender_username=msg.sender.username,
            receiver_id=msg.receiver_id,
            content=msg.content,
            created_at=msg.created_at,
            is_read=msg.is_read
        ) for msg in messages
    ]


@router.get("/unread")
async def unread_count(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Возвращает количество непрочитанных сообщений для текущего пользователя.
    """
    count = db.query(models.Message).filter(
        models.Message.receiver_id == current_user.id,
        models.Message.is_read == False
    ).count()
    return {"unread": count}


@router.get("/contacts", response_model=List[schemas.ContactOut])
async def get_contacts(
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Возвращает список контактов (пользователей, с которыми была переписка)
    с информацией о последнем сообщении и количестве непрочитанных.
    """
    # Подзапрос для получения всех участников переписки
    subq = db.query(models.Message.sender_id.label('user_id')).filter(
        models.Message.receiver_id == current_user.id
    ).union(
        db.query(models.Message.receiver_id.label('user_id')).filter(
            models.Message.sender_id == current_user.id
        )
    ).subquery()

    contacts = db.query(models.User).filter(models.User.id.in_(subq)).all()

    result = []
    for contact in contacts:
        last_msg = db.query(models.Message).filter(
            or_(
                and_(models.Message.sender_id == current_user.id, models.Message.receiver_id == contact.id),
                and_(models.Message.sender_id == contact.id, models.Message.receiver_id == current_user.id)
            )
        ).order_by(desc(models.Message.created_at)).first()

        unread = db.query(models.Message).filter(
            models.Message.sender_id == contact.id,
            models.Message.receiver_id == current_user.id,
            models.Message.is_read == False
        ).count()

        result.append({
            "user_id": contact.id,
            "username": contact.username,
            "is_teacher": contact.is_teacher,
            "last_message": last_msg.content if last_msg else None,
            "last_time": last_msg.created_at if last_msg else None,
            "unread": unread
        })

    return result