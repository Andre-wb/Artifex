import re
import logging
from datetime import datetime
from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import bindparam

from app.config import Config
from app.secure_cookie import create_secure_cookie
from app.email import safe_form_data, extract_form_data
from app.database import get_db
from app.models import User
from app.auth import get_current_user
from app.security_utils import (
    generate_double_csrf_token, timing_safe_endpoint,
    rate_limit_safe, validate_input_safe, sanitize_string,
    verify_csrf_token
)
from app.create_csrf_cookie import create_csrf_cookie
from app.templates import templates

router = APIRouter()
logger = logging.getLogger(__name__)

is_production = Config.ENVIRONMENT == 'production' if hasattr(Config, 'ENVIRONMENT') else False


def render_edit_profile_error(request, user, username, school, grade, error_msg):
    new_cookie_token, new_form_token = generate_double_csrf_token()
    response = templates.TemplateResponse("edit_profile.html", {
        "request": request,
        "error": error_msg,
        "user": user,
        "username": username,
        "school": school,
        "grade": grade,
        "reminder_hours": user.reminder_hours_before,
        "csrf_token": new_form_token
    })
    create_csrf_cookie(response, new_cookie_token)
    return response


@router.get("/profile", response_class=HTMLResponse)
@timing_safe_endpoint
@rate_limit_safe(max_calls=5, window=60)
@validate_input_safe
async def user_orders(
        request: Request,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    new_cookie_token, new_form_token = generate_double_csrf_token()

    response = templates.TemplateResponse(
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
async def edit_profile_page(request: Request, user: User = Depends(get_current_user)):
    cookie_token, form_token = generate_double_csrf_token()
    response = templates.TemplateResponse("edit_profile.html", {
        "request": request,
        "user": user,
        "school": user.school or "",
        "grade": user.grade or "",
        "is_teacher": user.is_teacher,
        "reminder_hours": user.reminder_hours_before,
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
        school: str = Form(...),
        grade: str = Form(None),
        reminder_hours: int = Form(24),
        csrf_token: str = Form(...),
        db: Session = Depends(get_db),
        user: User = Depends(get_current_user)
):
    cookie_csrf_token = request.cookies.get("csrf_token")
    if cookie_csrf_token:
        csrf_valid = verify_csrf_token(csrf_token, cookie_csrf_token)
        if not csrf_valid:
            new_cookie_token, new_form_token = generate_double_csrf_token()
            response = templates.TemplateResponse("error.html", {
                "request": request,
                "error": "Недействительный CSRF токен",
                "csrf_token": new_form_token
            }, status_code=400)
            create_csrf_cookie(response, new_cookie_token)
            return response

    username = sanitize_string(username.strip(), max_length=30)
    school = sanitize_string(school.strip(), max_length=100)
    grade = sanitize_string(grade.strip(), max_length=20) if grade else None

    username_pattern = r'^[a-zA-Z0-9_]{3,30}$'
    if not re.match(username_pattern, username):
        new_cookie_token, new_form_token = generate_double_csrf_token()
        response = templates.TemplateResponse("edit_profile.html", {
            "request": request,
            "error": "Имя пользователя должно содержать только буквы, цифры и подчеркивания, от 3 до 30 символов",
            "user": user,
            "school": school,
            "grade": grade,
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
        response = templates.TemplateResponse("edit_profile.html", {
            "request": request,
            "error": "Имя пользователя уже занято",
            "user": user,
            "school": school,
            "grade": grade,
            "csrf_token": new_form_token
        })
        create_csrf_cookie(response, new_cookie_token)
        return response

    if not school:
        new_cookie_token, new_form_token = generate_double_csrf_token()
        response = templates.TemplateResponse("edit_profile.html", {
            "request": request,
            "error": "Школа не может быть пустой",
            "user": user,
            "username": username,
            "school": school,
            "grade": grade,
            "csrf_token": new_form_token
        })
        create_csrf_cookie(response, new_cookie_token)
        return response

    if not user.is_teacher and not grade:
        new_cookie_token, new_form_token = generate_double_csrf_token()
        response = templates.TemplateResponse("edit_profile.html", {
            "request": request,
            "error": "Для ученика класс обязателен",
            "user": user,
            "username": username,
            "school": school,
            "grade": grade,
            "csrf_token": new_form_token
        })
        create_csrf_cookie(response, new_cookie_token)
        return response

    if reminder_hours < 1 or reminder_hours > 48:
        return render_edit_profile_error(
            request, user, username, school, grade,
            "Количество часов должно быть от 1 до 48"
        )

    user.username = username
    user.school = school
    user.grade = grade if not user.is_teacher else None
    user.reminder_hours_before = reminder_hours
    user.updated_at = datetime.utcnow()
    db.commit()

    new_cookie_token, new_form_token = generate_double_csrf_token()
    response = templates.TemplateResponse("message.html", {
        "request": request,
        "title": "Профиль обновлён",
        "message": "Ваш профиль успешно обновлён.",
        "csrf_token": new_form_token
    })
    create_csrf_cookie(response, new_cookie_token)
    return response