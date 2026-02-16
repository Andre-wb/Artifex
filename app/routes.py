"""
Модуль маршрутов (роутов) для FastAPI-приложения.
Содержит обработчики для главной страницы, регистрации, входа, профиля и т.д.
Использует формы, безопасность, валидацию и работу с базой данных.
"""

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
from .email import safe_form_data, send_confirmation_email, confirm_token, extract_form_data, generate_confirmation_token
from .database import get_db
from .models import User
from .auth import (
    get_current_user, get_current_user_optional,
    create_access_token, create_refresh_token
)
from .forms import register_form, login_form
from .security import (
    validate_password, check_password_against_user_data,
    hash_password, verify_password
)
from .security_utils import (
    generate_double_csrf_token, generate_simple_csrf_token,
    verify_double_csrf_token, verify_simple_csrf_token,
    timing_safe_endpoint, rate_limit_safe, validate_input_safe
)
from .create_csrf_cookie import create_csrf_cookie

router = APIRouter()
templates = Jinja2Templates(directory="templates")

logger = logging.getLogger(__name__)

# Секретный ключ для подписей (например, для подтверждения email)
JWT_SECRET = os.getenv('SECRET_KEY')
serializer = URLSafeTimedSerializer(JWT_SECRET)

# Флаг production (для безопасных cookie)
is_production = Config.ENVIRONMENT == 'production'


def get_server_time() -> str:
    """Возвращает текущее серверное время в формате YYYY-MM-DD HH:MM:SS."""
    return time.strftime('%Y-%m-%d %H:%M:%S')


# -------------------------------------------------------------------
# Публичные страницы
# -------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Главная страница."""
    return templates.TemplateResponse("base.html", {"request": request})


@router.get("/timetable", response_class=HTMLResponse)
async def timetable(request: Request):
    """Страница расписания."""
    return templates.TemplateResponse("timetable.html", {"request": request})


@router.get("/rating", response_class=HTMLResponse)
async def rating(request: Request):
    """Страница рейтингов."""
    return templates.TemplateResponse("rating.html", {"request": request})


@router.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    """Страница профиля пользователя."""
    return templates.TemplateResponse("profile.html", {"request": request})


# -------------------------------------------------------------------
# Регистрация
# -------------------------------------------------------------------

@router.post("/register")
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def register_user(
        request: Request,
        db: Session = Depends(get_db)
):
    """
    Обрабатывает POST-запрос на регистрацию нового пользователя.
    Выполняет валидацию полей, проверку уникальности, создание записи в БД,
    отправку письма с подтверждением email.
    """
    try:
        form_data = await safe_form_data(request)
        data = extract_form_data(form_data, ["username", "email", "phone", "password", "confirm"])
        username = data["username"]
        email = data["email"]
        phone = data["phone"]
        password = data["password"]
        confirm = data["confirm"]

        # Проверка заполнения всех полей
        if not all([username, email, phone, password, confirm]):
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Все поля обязательны для заполнения",
                "username": username,
                "email": email,
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        # Проверка совпадения паролей
        if password != confirm:
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Пароли должны совпадать",
                "username": username,
                "email": email,
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        # Проверка сложности пароля
        is_valid_password, password_error = validate_password(password)
        if not is_valid_password:
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": password_error,
                "username": username,
                "email": email,
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        # Проверка, что пароль не содержит личные данные
        is_valid_user_data, user_data_error = check_password_against_user_data(
            password=password,
            username=username,
            email=email
        )
        if not is_valid_user_data:
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": user_data_error,
                "username": username,
                "email": email,
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        # Нормализация телефона (только цифры)
        normalized_phone = re.sub(r'\D', '', phone)

        # Валидация email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Некорректный формат email",
                "username": username,
                "email": email,
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        # Валидация имени пользователя
        username_pattern = r'^[a-zA-Z0-9_]{3,30}$'
        if not re.match(username_pattern, username):
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Имя пользователя должно содержать только буквы, цифры и подчеркивания, от 3 до 30 символов",
                "username": username,
                "email": email,
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        # Валидация телефона (после нормализации)
        if not re.match(r'^[1-9]\d{9,14}$', normalized_phone):
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Некорректный формат телефона. Введите номер в формате: +7XXXXXXXXXX или 8XXXXXXXXXX",
                "username": username,
                "email": email,
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        # Проверка уникальности email, username, phone
        email_exists = db.query(User).filter(User.email == email).first() is not None
        username_exists = db.query(User).filter(User.username == username).first() is not None
        phone_exists = db.query(User).filter(User.phone == normalized_phone).first() is not None

        if email_exists:
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Email уже зарегистрирован",
                "username": username,
                "email": "",
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        if username_exists:
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Имя пользователя уже занято",
                "username": "",
                "email": email,
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        if phone_exists:
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": "Номер телефона уже зарегистрирован",
                "username": username,
                "email": email,
                "phone": "",
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        # Создание пользователя
        try:
            user = User(
                username=username,
                email=email,
                phone=normalized_phone,
                confirmed=False,
                is_admin=False,
                created_at=datetime.utcnow(),
                locked_until=None,
                failed_login_attempts=0
            )
            user.set_password(password)  # предполагается, что метод set_password хеширует пароль

            db.add(user)
            db.commit()
            db.refresh(user)

            logger.info(f"Новый пользователь зарегистрирован: ID={user.id}, username={username}")

            # Отправка письма с подтверждением
            token = generate_confirmation_token(user.email)
            email_sent = await send_confirmation_email(user.email, token, request)

            new_cookie_token, new_form_token = generate_double_csrf_token()

            if email_sent:
                response = templates.TemplateResponse(
                    "message.html",
                    {
                        "request": request,
                        "title": "Регистрация успешна",
                        "message": (
                            f"Регистрация завершена, {username}!<br><br>"
                            f"На ваш email <strong>{email}</strong> было отправлено письмо с ссылкой для подтверждения.<br>"
                            f"Пожалуйста, проверьте вашу почту и перейдите по ссылке в письме."
                        ),
                        "csrf_token": new_form_token
                    },
                )
                create_csrf_cookie(response, new_cookie_token)
                return response
            else:
                logger.warning(f"Email подтверждения не отправлен для пользователя {user.id}. Email: {email}")
                retry_token = generate_confirmation_token(user.email)
                response = templates.TemplateResponse(
                    "message.html",
                    {
                        "request": request,
                        "title": "Регистрация завершена",
                        "message": (
                            f"Ваш аккаунт <strong>{username}</strong> успешно создан!<br><br>"
                            f"Однако мы не смогли отправить письмо с подтверждением на ваш email.<br>"
                            f"Вы можете <a href='/resend-confirmation/{retry_token}' class='button'>отправить подтверждение повторно</a> или "
                            f"связаться с поддержкой."
                        ),
                        "csrf_token": new_form_token
                    }
                )
                create_csrf_cookie(response, new_cookie_token)
                return response

        except IntegrityError as e:
            db.rollback()
            error_message = "Произошла ошибка при сохранении данных. "
            if "user.email" in str(e):
                error_message += "Email уже используется."
            elif "user.username" in str(e):
                error_message += "Имя пользователя уже занято."
            elif "user.phone" in str(e):
                error_message += "Номер телефона уже используется."
            else:
                error_message += "Возможно, некоторые данные уже используются."

            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("register.html", {
                "request": request,
                "error": error_message,
                "username": username,
                "email": email,
                "phone": phone,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

    except Exception as e:
        db.rollback()
        logger.error(f"Критическая ошибка при регистрации пользователя: {str(e)}", exc_info=True)
        new_cookie_token, new_form_token = generate_double_csrf_token()
        response = templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": (
                    "Произошла внутренняя ошибка сервера при регистрации. "
                    "Пожалуйста, попробуйте позже или свяжитесь с поддержкой."
                ),
                "csrf_token": new_form_token
            },
            status_code=500
        )
        create_csrf_cookie(response, new_cookie_token)
        return response