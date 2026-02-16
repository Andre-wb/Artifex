"""
Модуль middleware для установки заголовков безопасности в HTTP-ответах.

Добавляет следующие заголовки:
- X-Frame-Options: DENY — защита от clickjacking.
- X-Content-Type-Options: nosniff — запрет MIME-сниффинга.
- X-XSS-Protection: 1; mode=block — включение встроенной защиты от XSS в браузерах.
- Referrer-Policy: strict-origin-when-cross-origin — ограничение передачи Referer.
- Permissions-Policy: ограничение доступа к геолокации, микрофону, камере.
- Cross-Origin-Opener-Policy: same-origin — изоляция окна.
- Cross-Origin-Resource-Policy: same-origin — ограничение загрузки ресурсов.
- Cross-Origin-Embedder-Policy: require-corp — требование CORP для загружаемых ресурсов.
- Strict-Transport-Security (HSTS) — принудительное HTTPS (в production с preload).
- X-Permitted-Cross-Domain-Policies: none — запрет политик cross-domain для Flash/PDF.
- Content-Security-Policy (CSP) — ограничение источников скриптов, стилей, шрифтов и т.д.
- Feature-Policy (устаревший аналог Permissions-Policy) — для обратной совместимости.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from .config import Config
import os

# Определяем, работаем ли в production (для HSTS и Secure cookie)
is_production = Config.ENVIRONMENT == 'production'


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware, добавляющий заголовки безопасности к каждому ответу.
    Для статических файлов заголовки не добавляются (кроме HSTS, если нужно).
    """

    async def dispatch(self, request, call_next):
        response = await call_next(request)

        # Не добавляем заголовки для статических файлов (они могут кешироваться и не требуют защиты)
        if not request.url.path.startswith('/static/'):
            # Базовые защитные заголовки
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
            response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

            # HSTS (HTTP Strict Transport Security)
            if is_production:
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
            else:
                response.headers["Strict-Transport-Security"] = "max-age=86400; includeSubDomains"

            response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

            # Content Security Policy (CSP) – необходимо настроить под конкретный проект.
            # Здесь приведён базовый вариант, разрешающий только ресурсы с того же источника.
            # Если вы используете внешние библиотеки (например, CDN), добавьте их домены.
            csp_policy = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'report-sample'; "
                "style-src 'self' 'unsafe-inline' 'report-sample'; "
                "font-src 'self'; "
                "img-src 'self' data: https: blob:; "
                "connect-src 'self'; "
                "frame-src 'none'; "
                "frame-ancestors 'none'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "upgrade-insecure-requests; "
                "block-all-mixed-content;"
            )

            response.headers["Content-Security-Policy"] = csp_policy

            # Устаревший заголовок Feature-Policy (для обратной совместимости)
            response.headers["Feature-Policy"] = (
                "geolocation 'none'; "
                "microphone 'none'; "
                "camera 'none'; "
                "payment 'none'"
            )

        return response