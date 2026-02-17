from fastapi import APIRouter, Request, Depends, HTTPException, Form, Response, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import or_, bindparam
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
from .secure_cookie import create_secure_cookie
from .email import safe_form_data, send_confirmation_email, confirm_token, extract_form_data, generate_confirmation_token
from .database import get_db
from .models import User, RefreshToken
from .auth import (
    get_current_user, get_current_user_optional,
    create_access_token, create_refresh_token, verify_refresh_token
)
from .forms import register_form, login_form
from .security import (
    validate_password, check_password_against_user_data,
    hash_password, verify_password
)
from .security_utils import (
    generate_double_csrf_token, generate_simple_csrf_token,
    verify_double_csrf_token, verify_simple_csrf_token,
    timing_safe_endpoint, rate_limit_safe, validate_input_safe, sanitize_string,
    verify_csrf_token
)
from .create_csrf_cookie import create_csrf_cookie

router = APIRouter()
templates = Jinja2Templates(directory="templates")
app = FastAPI()

logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv('SECRET_KEY')
serializer = URLSafeTimedSerializer(JWT_SECRET)

is_production = Config.ENVIRONMENT == 'production' if hasattr(Config, 'ENVIRONMENT') else False

def get_server_time() -> str:
    return time.strftime('%Y-%m-%d %H:%M:%S')

@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("base.html", {"request": request})

@router.get("/timetable", response_class=HTMLResponse)
async def timetable(request: Request):
    return templates.TemplateResponse("timetable.html", {"request": request})

@router.get("/rating", response_class=HTMLResponse)
async def rating(request: Request):
    return templates.TemplateResponse("rating.html", {"request": request})

@router.get("/diary-page", response_class=HTMLResponse)
async def diary_redirect():
    return RedirectResponse(url="/diary")

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """
    Обрабатывает GET-запрос для отображения страницы регистрации.
    Генерирует и устанавливает CSRF-токены (двойная отправка).

    Аргументы:
        request (Request): объект запроса FastAPI.

    Возвращает:
        TemplateResponse: отрендеренный шаблон register.html с CSRF-токеном в форме и cookie.
    """
    cookie_token, form_token = generate_double_csrf_token()

    request.state.csrf_token = cookie_token
    request.state._csrf_cookie_token = cookie_token

    logger.debug(f"GET /register: Сгенерированы токены. Cookie: {cookie_token[:10]}..., Form: {form_token[:20]}...")

    response = request.app.state.templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "csrf_token": form_token
        }
    )

    create_csrf_cookie(response, cookie_token)

    return response

@router.post("/register")
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def register_user(
        request: Request,
        db: Session = Depends(get_db)
):
    try:
        form_data = await safe_form_data(request)
        data = extract_form_data(form_data, ["username", "email", "phone", "password", "confirm"])
        username = data["username"]
        email = data["email"]
        phone = data["phone"]
        password = data["password"]
        confirm = data["confirm"]

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

        normalized_phone = re.sub(r'\D', '', phone)

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
            user.set_password(password)

            db.add(user)
            db.commit()
            db.refresh(user)

            logger.info(f"Новый пользователь зарегистрирован: ID={user.id}, username={username}")

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

@router.post("/api/refresh-token")
async def refresh_token(
        request: Request,
        db: Session = Depends(get_db)
):
    """
    Обрабатывает POST-запрос на обновление access-токена с использованием refresh-токена.
    Проверяет наличие refresh-токена в cookies, валидирует его и возвращает новый access-токен.

    Аргументы:
        request (Request): объект запроса FastAPI.
        db (Session): сессия базы данных (зависимость).

    Возвращает:
        JSONResponse: ответ с новым access-токеном и информацией об успехе,
                      либо ошибкой с соответствующим статус-кодом.
    """
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    try:
        user = verify_refresh_token(refresh_token, db)

        new_access_token = create_access_token(data={"sub": str(user.id)})

        response = JSONResponse({
            "success": True,
            "access_token": new_access_token,
            "expires_in": 900
        })

        create_secure_cookie(response, "access_token", new_access_token, 15*60)
        return response

    except HTTPException as e:
        response = JSONResponse({"success": False, "error": e.detail}, status_code=e.status_code)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response

@router.get("/confirm-email/{token}")
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def confirm_email(token: str, request: Request, db: Session = Depends(get_db)):
    """
    Подтверждает email пользователя по токену, переданному в ссылке из письма.
    При успешном подтверждении обновляет поле confirmed в базе данных.
    """
    email = confirm_token(token)
    if not email:
        return request.app.state.templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Неверный или просроченный токен"
        }, status_code=400)

    user = db.query(User).filter(User.email == email).first()
    if not user:
        return request.app.state.templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Пользователь не найден"
        }, status_code=404)

    if not user.confirmed:
        user.confirmed = True
        db.commit()

    new_cookie_token, new_form_token = generate_double_csrf_token()

    response = request.app.state.templates.TemplateResponse("message.html", {
        "request": request,
        "title": "Email подтверждён",
        "message": "Ваш email успешно подтвержден. Теперь вы можете войти в систему.",
        "csrf_token": new_form_token
    })

    create_csrf_cookie(response, new_cookie_token)
    return response

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """
    Обрабатывает GET-запрос для отображения страницы входа.
    Генерирует и устанавливает CSRF-токены (двойная отправка).

    Аргументы:
        request (Request): объект запроса FastAPI.

    Возвращает:
        TemplateResponse: отрендеренный шаблон login.html с CSRF-токеном в форме и cookie.
    """
    cookie_token, form_token = generate_double_csrf_token()

    request.state.csrf_token = cookie_token
    request.state._csrf_cookie_token = cookie_token

    logger.debug(f"GET /login: Сгенерированы токены. Cookie: {cookie_token[:10]}..., Form: {form_token[:20]}...")

    response = request.app.state.templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "csrf_token": form_token
        }
    )

    create_csrf_cookie(response, cookie_token)
    return response

@router.post("/login")
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def login(
        request: Request,
        db: Session = Depends(get_db)
):
    """
    Обрабатывает POST-запрос на аутентификацию пользователя.
    Проверяет учётные данные, управляет блокировкой при множественных неудачных попытках,
    при успехе создаёт access и refresh токены и устанавливает их в cookie.
    """
    try:
        form_data = await safe_form_data(request)

        data = extract_form_data(form_data, ["credential", "password"])
        credential = data["credential"]
        password = data["password"]

        credential = sanitize_string(credential.strip(), max_length=255)
        password = sanitize_string(password, max_length=255)

        if not credential or not password:
            new_cookie_token, new_form_token = generate_double_csrf_token()

            response = request.app.state.templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Все поля обязательны для заполнения",
                "credential": credential,
                "csrf_token": new_form_token
            })

            create_csrf_cookie(response, new_cookie_token)
            return response

        user = db.query(User).filter(
            or_(
                User.email == bindparam('cred'),
                User.phone == bindparam('cred'),
                User.username == bindparam('cred')
            )
        ).params(cred=credential).first()

        if user and user.locked_until and user.locked_until > datetime.utcnow():
            _ = user.check_password(password)
            logger.warning(f"Попытка входа в заблокированный аккаунт: {credential}")

            new_cookie_token, new_form_token = generate_double_csrf_token()

            response = request.app.state.templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Аккаунт временно заблокирован. Попробуйте позже.",
                "credential": credential,
                "csrf_token": new_form_token
            })

            create_csrf_cookie(response, new_cookie_token)
            return response

        if user and user.check_password(password):
            if user.failed_login_attempts > 0:
                user.failed_login_attempts = 0
                user.locked_until = None
                db.commit()

            if not user.confirmed:
                logger.warning(f"Попытка входа без подтверждения email: {credential}")

                new_cookie_token, new_form_token = generate_double_csrf_token()

                response = request.app.state.templates.TemplateResponse("login.html", {
                    "request": request,
                    "error": "Подтвердите ваш Email. Проверьте почту.",
                    "credential": credential,
                    "csrf_token": new_form_token
                })

                create_csrf_cookie(response, new_cookie_token)
                return response

            access_token = create_access_token(data={"sub": str(user.id)})
            refresh_token, refresh_expires = create_refresh_token(user.id, db)

            response = RedirectResponse("/profile", status_code=303)

            create_secure_cookie(response, "access_token", access_token, 15*60)
            create_secure_cookie(response, "refresh_token", refresh_token, 180*24*3600)

            new_cookie_token, new_form_token = generate_double_csrf_token()
            create_csrf_cookie(response, new_cookie_token)

            logger.info(f"Успешный вход пользователя: {user.username} (ID: {user.id})")
            return response
        else:
            if user:
                user.failed_login_attempts += 1

                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    logger.warning(f"Аккаунт {user.username} заблокирован до {user.locked_until}")

                db.commit()

            new_cookie_token, new_form_token = generate_double_csrf_token()

            response = request.app.state.templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Неверные email, телефон, имя пользователя или пароль",
                "credential": credential,
                "csrf_token": new_form_token
            })

            create_csrf_cookie(response, new_cookie_token)
            return response

    except Exception as e:
        logger.error(f"Ошибка при входе: {str(e)}", exc_info=True)

        new_cookie_token, new_form_token = generate_double_csrf_token()

        response = request.app.state.templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Внутренняя ошибка сервера. Пожалуйста, попробуйте позже.",
            "csrf_token": new_form_token
        }, status_code=500)

        create_csrf_cookie(response, new_cookie_token)
        return response

@router.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """
    Обрабатывает GET-запрос на выход пользователя из системы.
    Отзывает все refresh-токены пользователя, удаляет cookies с токенами и
    перенаправляет на страницу входа.

    Аргументы:
        request (Request): объект запроса FastAPI.
        db (Session): сессия базы данных (зависимость).

    Возвращает:
        RedirectResponse: перенаправление на /login с очищенными cookies.
    """
    try:
        access_token = request.cookies.get("access_token")
        if access_token:
            from .auth import decode_token
            payload = decode_token(access_token)
            user_id = payload.get("sub")
            if user_id:
                db.query(RefreshToken).filter(RefreshToken.user_id == user_id).update({
                    "revoked_at": datetime.utcnow()
                })
                db.commit()
    except Exception as e:
        logger.error(f"Ошибка при отзыве refresh tokens: {e}")

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    new_cookie_token, new_form_token = generate_double_csrf_token()
    create_csrf_cookie(response, new_cookie_token)

    return response

# -------------------------------------------------------------------
# Профиль
# -------------------------------------------------------------------

@router.get("/profile", response_class=HTMLResponse)
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def user_orders(
        request: Request,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    """
    Обрабатывает GET-запрос для отображения страницы профиля пользователя.
    Генерирует и устанавливает CSRF-токены (двойная отправка) для защиты форм на странице.
    Требует аутентификации пользователя.

    Аргументы:
        request (Request): объект запроса FastAPI.
        user (User): текущий аутентифицированный пользователь (зависимость).
        db (Session): сессия базы данных (зависимость).

    Возвращает:
        TemplateResponse: отрендеренный шаблон profile.html с данными пользователя и CSRF-токеном.
    """
    new_cookie_token, new_form_token = generate_double_csrf_token()

    response = request.app.state.templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": user,
            "csrf_token": new_form_token
        }
    )
    create_csrf_cookie(response, new_cookie_token)
    return response

@router.get("/edit_profile", response_class=HTMLResponse)
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def edit_profile_page(request: Request, user: User = Depends(get_current_user)):
    """
    Обрабатывает GET-запрос для отображения страницы редактирования профиля.
    Генерирует и устанавливает CSRF-токены (двойная отправка). Требует аутентификации.

    Аргументы:
        request (Request): объект запроса FastAPI.
        user (User): текущий аутентифицированный пользователь (зависимость).

    Возвращает:
        TemplateResponse: отрендеренный шаблон edit_profile.html с данными пользователя и CSRF-токеном.
    """
    cookie_token, form_token = generate_double_csrf_token()

    response = request.app.state.templates.TemplateResponse("edit_profile.html", {
        "request": request,
        "user": user,
        "csrf_token": form_token
    })

    create_csrf_cookie(response, cookie_token)
    return response

@router.post("/edit_profile")
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def edit_profile(
        request: Request,
        username: str = Form(...),
        csrf_token: str = Form(...),
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    """
    Обрабатывает POST-запрос на обновление профиля пользователя (имени пользователя).
    Проверяет CSRF-токен, валидирует новое имя, проверяет уникальность и сохраняет изменения.
    """
    cookie_csrf_token = request.cookies.get("csrf_token")
    if cookie_csrf_token:
        csrf_valid = verify_csrf_token(csrf_token, cookie_csrf_token)
        if not csrf_valid:
            new_cookie_token, new_form_token = generate_double_csrf_token()

            response = request.app.state.templates.TemplateResponse("error.html", {
                "request": request,
                "error": "Недействительный CSRF токен",
                "csrf_token": new_form_token
            }, status_code=400)

            create_csrf_cookie(response, new_cookie_token)
            return response

    username = sanitize_string(username.strip(), max_length=30)

    username_pattern = r'^[a-zA-Z0-9_]{3,30}$'
    if not re.match(username_pattern, username):
        new_cookie_token, new_form_token = generate_double_csrf_token()

        response = request.app.state.templates.TemplateResponse("edit_profile.html", {
            "request": request,
            "error": "Имя пользователя должно содержать только буквы, цифры и подчеркивания, от 3 до 30 символов",
            "user": user,
            "csrf_token": new_form_token
        })

        create_csrf_cookie(response, new_cookie_token)
        return response

    existing_user = db.query(User).filter(
        User.username == bindparam('username'),
        User.id != bindparam('user_id')
    ).params(username=username, user_id=user.id).first()

    if existing_user:
        new_cookie_token, new_form_token = generate_double_csrf_token()

        response = request.app.state.templates.TemplateResponse("edit_profile.html", {
            "request": request,
            "error": "Имя пользователя уже занято",
            "user": user,
            "csrf_token": new_form_token
        })

        create_csrf_cookie(response, new_cookie_token)
        return response

    user.username = username
    user.updated_at = datetime.utcnow()
    db.commit()

    new_cookie_token, new_form_token = generate_double_csrf_token()

    response = request.app.state.templates.TemplateResponse("message.html", {
        "request": request,
        "title": "Профиль обновлён",
        "message": "Ваш профиль успешно обновлён.",
        "csrf_token": new_form_token
    })

    create_csrf_cookie(response, new_cookie_token)
    return response