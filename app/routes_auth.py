import re
import logging
import os
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, bindparam
from sqlalchemy.exc import IntegrityError

from app.config import Config
from app.secure_cookie import create_secure_cookie
from app.email import (
    safe_form_data, send_confirmation_email, confirm_token,
    extract_form_data, generate_confirmation_token
)
from app.database import get_db
from app.models import User, RefreshToken, TwoFactorCode
from app.auth import (
    get_current_user, create_access_token, create_refresh_token,
    verify_refresh_token, generate_2fa_code, hash_2fa_code,
    verify_2fa_code, create_2fa_token, verify_2fa_token,
    create_trusted_cookie, verify_trusted_cookie, send_2fa_email
)
from app.security import validate_password, check_password_against_user_data
from app.security_utils import (
    generate_double_csrf_token, timing_safe_endpoint,
    rate_limit_safe, validate_input_safe, sanitize_string
)
from app.create_csrf_cookie import create_csrf_cookie
from app.templates import templates

router = APIRouter()
logger = logging.getLogger(__name__)

JWT_SECRET = os.getenv('SECRET_KEY')

is_production = Config.ENVIRONMENT == 'production' if hasattr(Config, 'ENVIRONMENT') else False


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    cookie_token, form_token = generate_double_csrf_token()
    request.state.csrf_token = cookie_token
    response = templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "csrf_token": form_token,
            "school": "",
            "grade": "",
            "is_teacher": False
        }
    )
    create_csrf_cookie(response, cookie_token)
    return response


@router.post("/register")
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def register_user(request: Request, db: Session = Depends(get_db)):
    try:
        form_data = await safe_form_data(request)
        data = extract_form_data(form_data, ["username", "email", "phone", "password", "confirm", "school", "grade", "is_teacher"])
        username = data["username"]
        email = data["email"]
        phone = data["phone"]
        password = data["password"]
        confirm = data["confirm"]
        school = data.get("school")
        grade = data.get("grade")
        is_teacher = data.get("is_teacher") == "true"

        if not all([username, email, phone, password, confirm, school, grade]):
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
                failed_login_attempts=0,
                is_teacher=is_teacher,
                school=school,
                grade=grade
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
                "school": school,
                "grade": grade,
                "is_teacher": is_teacher,
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
async def refresh_token(request: Request, db: Session = Depends(get_db)):
    refresh_token_cookie = request.cookies.get("refresh_token")
    if not refresh_token_cookie:
        raise HTTPException(status_code=401, detail="No refresh token")

    try:
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        user, new_refresh_token, new_expires_at = verify_refresh_token(
            refresh_token_cookie, db,
            current_ip=client_ip,
            current_ua=user_agent
        )

        new_access_token = create_access_token(data={"sub": str(user.id)})

        response = JSONResponse({
            "success": True,
            "access_token": new_access_token,
            "expires_in": 900
        })

        create_secure_cookie(response, "access_token", new_access_token, 15*60)
        create_secure_cookie(response, "refresh_token", new_refresh_token, 180*24*3600)

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
    email = confirm_token(token)
    if not email:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Неверный или просроченный токен"
        }, status_code=400)

    user = db.query(User).filter(User.email == email).first()
    if not user:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Пользователь не найден"
        }, status_code=404)

    if not user.confirmed:
        user.confirmed = True
        db.commit()

    new_cookie_token, new_form_token = generate_double_csrf_token()

    response = templates.TemplateResponse("message.html", {
        "request": request,
        "title": "Email подтверждён",
        "message": "Ваш email успешно подтвержден. Теперь вы можете войти в систему.",
        "csrf_token": new_form_token
    })

    create_csrf_cookie(response, new_cookie_token)
    return response


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    cookie_token, form_token = generate_double_csrf_token()

    request.state.csrf_token = cookie_token
    request.state._csrf_cookie_token = cookie_token

    response = templates.TemplateResponse(
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
async def login(request: Request, db: Session = Depends(get_db)):
    try:
        form_data = await safe_form_data(request)

        data = extract_form_data(form_data, ["credential", "password"])
        credential = data["credential"]
        password = data["password"]

        credential = sanitize_string(credential.strip(), max_length=255)
        password = sanitize_string(password, max_length=255)

        if not credential or not password:
            new_cookie_token, new_form_token = generate_double_csrf_token()

            response = templates.TemplateResponse("login.html", {
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
            response = templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Аккаунт временно заблокирован. Попробуйте позже.",
                "credential": credential,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        if not user or not user.check_password(password):
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                db.commit()
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Неверные email, телефон, имя пользователя или пароль",
                "credential": credential,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        if user.failed_login_attempts > 0:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.commit()

        if not user.confirmed:
            logger.warning(f"Попытка входа без подтверждения email: {credential}")
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Подтвердите ваш Email. Проверьте почту.",
                "credential": credential,
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        trusted_token = request.cookies.get("trusted_2fa")
        if trusted_token:
            trusted_user_id = verify_trusted_cookie(trusted_token)
            if trusted_user_id == user.id:
                client_ip = request.client.host if request.client else None
                user_agent = request.headers.get("user-agent")

                refresh_token, refresh_expires = create_refresh_token(
                    user.id, db,
                    ip_address=client_ip,
                    user_agent=user_agent
                )
                access_token = create_access_token(data={"sub": str(user.id)})

                response = RedirectResponse("/profile", status_code=303)

                create_secure_cookie(response, "access_token", access_token, 15*60)
                create_secure_cookie(response, "refresh_token", refresh_token, 180*24*3600)

                response.set_cookie(
                    key="trusted_2fa",
                    value=create_trusted_cookie(user.id),
                    httponly=True,
                    secure=is_production,
                    samesite='Lax' if is_production else 'None',
                    max_age=900,
                    path="/"
                )

                new_cookie_token, new_form_token = generate_double_csrf_token()
                create_csrf_cookie(response, new_cookie_token)

                logger.info(f"Успешный вход (доверенное устройство): {user.username} (ID: {user.id})")
                return response

        code = generate_2fa_code()
        code_hash = hash_2fa_code(code)
        expires_at = datetime.utcnow() + timedelta(minutes=5)

        db.query(TwoFactorCode).filter(TwoFactorCode.user_id == user.id).delete()
        db.add(TwoFactorCode(
            user_id=user.id,
            code_hash=code_hash,
            expires_at=expires_at
        ))
        db.commit()

        if not await send_2fa_email(user, code):
            logger.error(f"Failed to send 2FA email to {user.email}")
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Не удалось отправить код подтверждения. Попробуйте позже.",
                "csrf_token": new_form_token
            })
            create_csrf_cookie(response, new_cookie_token)
            return response

        twofa_token = create_2fa_token(user.id)

        new_cookie_token, new_form_token = generate_double_csrf_token()
        response = templates.TemplateResponse("verify_2fa.html", {
            "request": request,
            "email": user.email,
            "csrf_token": new_form_token
        })

        response.set_cookie(
            key="2fa_token",
            value=twofa_token,
            httponly=True,
            secure=is_production,
            samesite='Lax' if is_production else 'None',
            max_age=2592000,
            path="/"
        )
        create_csrf_cookie(response, new_cookie_token)

        logger.info(f"2FA код отправлен для пользователя: {user.username}")
        return response

    except Exception as e:
        logger.error(f"Ошибка при входе: {str(e)}", exc_info=True)
        new_cookie_token, new_form_token = generate_double_csrf_token()
        response = templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Внутренняя ошибка сервера. Пожалуйста, попробуйте позже.",
            "csrf_token": new_form_token
        }, status_code=500)
        create_csrf_cookie(response, new_cookie_token)
        return response


@router.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    try:
        access_token = request.cookies.get("access_token")
        if access_token:
            from app.auth import decode_token
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


@router.post("/verify-2fa")
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def verify_2fa(request: Request, code: str = Form(...), db: Session = Depends(get_db)):
    twofa_token = request.cookies.get("2fa_token")
    if not twofa_token:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Сессия истекла. Войдите снова."
        })

    user_id = verify_2fa_token(twofa_token)
    if not user_id:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Недействительная сессия. Войдите снова."
        })

    twofa_code = db.query(TwoFactorCode).filter(
        TwoFactorCode.user_id == user_id,
        TwoFactorCode.expires_at > datetime.utcnow()
    ).first()

    if not twofa_code:
        return templates.TemplateResponse("verify_2fa.html", {
            "request": request,
            "error": "Код истёк. Запросите новый."
        })

    if twofa_code.attempts >= 5:
        db.delete(twofa_code)
        db.commit()
        return templates.TemplateResponse("verify_2fa.html", {
            "request": request,
            "error": "Слишком много неверных попыток. Начните вход заново."
        })

    if verify_2fa_code(code, twofa_code.code_hash):
        db.delete(twofa_code)
        db.commit()

        user = db.query(User).get(user_id)
        if not user:
            return templates.TemplateResponse("login.html", {"request": request, "error": "Пользователь не найден"})

        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        refresh_token, refresh_expires = create_refresh_token(user.id, db, ip_address=client_ip, user_agent=user_agent)
        access_token = create_access_token(data={"sub": str(user.id)})

        response = RedirectResponse("/profile", status_code=303)
        create_secure_cookie(response, "access_token", access_token, 15*60)
        create_secure_cookie(response, "refresh_token", refresh_token, 180*24*3600)

        response.set_cookie(
            key="trusted_2fa",
            value=create_trusted_cookie(user.id),
            httponly=True,
            secure=is_production,
            samesite='Lax' if is_production else 'None',
            max_age=2592000,
            path="/"
        )

        response.delete_cookie("2fa_token", path="/")

        new_cookie_token, new_form_token = generate_double_csrf_token()
        create_csrf_cookie(response, new_cookie_token)

        return response
    else:
        twofa_code.attempts += 1
        db.commit()
        return templates.TemplateResponse("verify_2fa.html", {
            "request": request,
            "error": "Неверный код. Попробуйте снова.",
        })


@router.post("/resend-2fa")
async def resend_2fa(request: Request, db: Session = Depends(get_db)):
    twofa_token = request.cookies.get("2fa_token")
    if not twofa_token:
        return JSONResponse({"success": False, "error": "Сессия не найдена"}, status_code=400)

    user_id = verify_2fa_token(twofa_token)
    if not user_id:
        return JSONResponse({"success": False, "error": "Сессия истекла"}, status_code=400)

    user = db.query(User).get(user_id)
    if not user:
        return JSONResponse({"success": False, "error": "Пользователь не найден"}, status_code=400)

    db.query(TwoFactorCode).filter(TwoFactorCode.user_id == user_id).delete()

    code = generate_2fa_code()
    code_hash = hash_2fa_code(code)
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.add(TwoFactorCode(user_id=user_id, code_hash=code_hash, expires_at=expires_at))
    db.commit()

    if await send_2fa_email(user, code):
        return JSONResponse({"success": True})
    else:
        return JSONResponse({"success": False, "error": "Ошибка отправки письма"}, status_code=500)