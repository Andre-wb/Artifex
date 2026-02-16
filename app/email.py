from fastapi import APIRouter, Request, Depends, HTTPException, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import or_, bindparam  # <-- добавлен импорт bindparam
from typing import Optional
from sqlalchemy.exc import IntegrityError
import re
import logging
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import os

from .config import Config

logger = logging.getLogger(__name__)
JWT_SECRET = os.getenv('SECRET_KEY')
serializer = URLSafeTimedSerializer(JWT_SECRET)

# Флаг production (для безопасных cookie)
is_production = Config.ENVIRONMENT == 'production'

def generate_confirmation_token(email: str) -> str:
    """
    Генерирует подписанный токен для подтверждения email.
    Использует itsdangerous.URLSafeTimedSerializer.
    """
    return serializer.dumps(email, salt="email-confirm")


def confirm_token(token: str, expiration: int = 3600):
    """
    Проверяет токен подтверждения email.
    Возвращает email, если токен валиден и не истёк, иначе False.
    """
    try:
        return serializer.loads(token, salt="email-confirm", max_age=expiration)
    except (SignatureExpired, BadSignature):
        return False


async def safe_form_data(request: Request):
    """
    Безопасно извлекает данные формы из request.
    Сначала пытается получить данные, уже сохранённые в request.state (например, middleware),
    иначе читает форму напрямую.
    """
    logger.debug(f"safe_form_data: Проверка request.state...")

    if hasattr(request.state, '_form_data'):
        logger.debug(f"safe_form_data: Используем _form_data из middleware")
        return request.state._form_data
    elif hasattr(request.state, 'form_data'):
        logger.debug(f"safe_form_data: Используем form_data из middleware")
        return request.state.form_data
    else:
        logger.debug(f"safe_form_data: Читаем форму из request")
        form = await request.form()
        logger.debug(f"safe_form_data: Прочитано полей: {len(form)}")
        return form


def extract_form_data(form_data, fields: list) -> dict:
    """
    Извлекает указанные поля из данных формы, нормализует их (строки, обрезка пробелов).
    Для полей, которые могут быть списками (например, при множественных значениях),
    берётся первый элемент.

    Аргументы:
        form_data: словарь или объект формы (может быть dict или FormData).
        fields: список имён полей для извлечения.

    Возвращает:
        Словарь {имя_поля: значение}.
    """
    logger.debug(f"extract_form_data: Тип form_data: {type(form_data)}")

    if isinstance(form_data, dict):
        logger.debug(f"extract_form_data: Ключи в form_data: {list(form_data.keys())}")
        for key, value in form_data.items():
            logger.debug(f"extract_form_data: {key} = {value}, type: {type(value)}")

    result = {}
    for field in fields:
        if isinstance(form_data, dict):
            value = form_data.get(field, "")
            logger.debug(f"extract_form_data: поле {field}, значение {value}, тип {type(value)}")

            if isinstance(value, list):
                logger.debug(f"extract_form_data: {field} - это список, длина: {len(value)}")
                if len(value) > 0:
                    value = value[0]
                    logger.debug(f"extract_form_data: взято первое значение: {value}")
                else:
                    value = ""

            if isinstance(value, str):
                result[field] = value.strip()
            else:
                result[field] = str(value) if value is not None else ""
        else:
            # form_data может быть объектом Starlette FormData
            value = form_data.get(field, "")
            if isinstance(value, list):
                value = value[0] if value else ""
            result[field] = value.strip() if isinstance(value, str) else str(value)

        # Маскируем пароли в логах
        logger.debug(f"extract_form_data: результат для {field} = {'*' * len(result[field]) if field in ['password', 'confirm'] else result[field]}")

    return result


async def send_confirmation_email(user_email: str, token: str, request: Request) -> bool:
    """
    Отправляет письмо с подтверждением email.
    Возвращает True, если письмо успешно отправлено.
    """
    msg = MIMEMultipart()
    msg['From'] = Config.SMTP_USERNAME
    msg['To'] = user_email
    msg['Subject'] = 'Подтвердите ваш email'

    confirm_url = f"{request.base_url}confirm-email/{token}"
    logger.debug(f"Confirmation URL = {confirm_url}")

    html_content = f"""
    <html><body>
      <p>Здравствуйте! Это приложение Artifex!<br>
      Чтобы подтвердить ваш Email, нажмите на ссылку ниже:</p>
      <p><a href="{confirm_url}">Подтвердить Email</a></p>
      <p>Если вы не регистрировались, проигнорируйте это письмо.</p>
    </body></html>
    """
    msg.attach(MIMEText(html_content, 'html'))

    try:
        with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT) as server:
            server.starttls()
            server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Ошибка отправки email: {e}")
        return False