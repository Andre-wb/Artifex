"""
Модуль для безопасного создания CSRF-токена в cookie.
Содержит функцию create_csrf_cookie, которая устанавливает cookie с именем "csrf_token",
используя правильные флаги безопасности в зависимости от окружения (production/development).
"""

from .config import Config
from fastapi import Response

# Определяем, работает ли приложение в production-режиме.
# Предполагается, что Config.ENVIRONMENT содержит булево значение или строку,
# которая приводится к булю (например, True/False или 'production').
is_production = Config.ENVIRONMENT


def create_csrf_cookie(response: Response, csrf_token: str):
    """
    Устанавливает безопасный CSRF-токен в cookie ответа.

    Параметры:
        response (Response): Объект ответа FastAPI, в который будет добавлена cookie.
        csrf_token (str): Значение CSRF-токена (обычно генерируется через secrets.token_urlsafe).

    Поведение:
        - HttpOnly: True – cookie недоступна из JavaScript (защита от XSS).
        - Secure: зависит от is_production (True в production, False в development).
          В production cookie передаётся только по HTTPS.
        - SameSite: 'Lax' в production (защита от CSRF с умеренными ограничениями),
                    'None' в development (позволяет кросс-доменные запросы при отладке).
        - Max-Age: 86400 секунд (1 сутки) – срок жизни cookie.
        - Path: '/' – cookie действует для всех путей домена.

    Пример:
        >>> from fastapi import Response
        >>> from .security_utils import generate_simple_csrf_token
        >>> response = Response()
        >>> token = generate_simple_csrf_token()
        >>> create_csrf_cookie(response, token)
        # В production установятся флаги: HttpOnly, Secure, SameSite=Lax
    """
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=True,
        secure=is_production,
        samesite='Lax' if is_production else 'None',
        max_age=86400,  # 1 день
        path="/"
    )