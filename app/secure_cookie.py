"""
Модуль для безопасного создания HTTP cookies в FastAPI-приложении.
Содержит функцию create_secure_cookie, которая устанавливает cookie
с флагами HttpOnly, Secure и SameSite в зависимости от окружения (production/development).
"""

from .config import Config
from fastapi import Response
import logging

logger = logging.getLogger(__name__)

is_production = Config.ENVIRONMENT == 'production'

def create_secure_cookie(response: Response, name: str, value: str, max_age: int):
    """
    Безопасно устанавливает cookie в HTTP-ответе.

    Параметры:
        response (Response): Объект ответа FastAPI, в который будет добавлена cookie.
        name (str): Имя cookie.
        value (str): Значение cookie.
        max_age (int): Время жизни cookie в секундах. Определяет, как долго браузер
                       будет хранить cookie (атрибут Max-Age).

    Поведение:
        - HttpOnly: True – cookie недоступна из JavaScript (защита от XSS).
        - Secure: зависит от значения is_production (True в production, False в development).
          В production cookie передаётся только по HTTPS.
        - SameSite: 'Lax' в production (защита от CSRF с умеренными ограничениями),
                    'None' в development (позволяет кросс-доменные запросы при отладке).
        - Path: '/' – cookie действует для всех путей домена.
        - Domain: None – cookie привязывается к текущему домену (без поддоменов).

    Пример:
        >>> from fastapi import Response
        >>> response = Response()
        >>> create_secure_cookie(response, "access_token", "jwt-token", 3600)
        # В production установятся флаги: HttpOnly, Secure, SameSite=Lax
    """

    response.set_cookie(
        key=name,
        value=value,
        httponly=True,
        secure=is_production,
        samesite='Lax' if is_production else 'None',
        max_age=max_age,
        path='/',
        domain=None,
    )