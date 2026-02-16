"""
Модуль middleware для FastAPI-приложения.
Содержит набор промежуточных слоёв (middleware), обеспечивающих:
- автоматическое обновление access-токена (TokenRefreshMiddleware),
- защиту от CSRF-атак (CSRFMiddleware),
- установку заголовков безопасности (SecurityHeadersMiddleware),
- ограничение частоты запросов (RateLimitMiddleware) — используется как запасной вариант,
- логирование входящих запросов (LoggingMiddleware).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
import logging
import secrets
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)


class TokenRefreshMiddleware(BaseHTTPMiddleware):
    """
    Middleware для автоматического обновления access-токена с использованием refresh-токена.

    Если в запросе отсутствует access_token, но присутствует refresh_token,
    middleware пытается верифицировать refresh_token и, в случае успеха,
    создаёт новый access_token и устанавливает его в cookie.

    Исключения (пути, не требующие токена) заданы списком.
    """

    async def dispatch(self, request: Request, call_next):
        # Пропускаем статические файлы, открытые эндпоинты и WebSocket без проверки
        if (request.url.path.startswith('/static') or
                request.url.path in [
                    '/login', '/register', '/api/refresh-token',
                    '/api/auth/login', '/api/auth/register',
                    '/logout', '/confirm-email/', '/resend-confirmation',
                    '/favicon.ico', '/health', '/metrics'
                ] or
                request.headers.get("upgrade", "").lower() == "websocket"):
            return await call_next(request)

        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")

        # Если access отсутствует, но refresh есть – пытаемся обновить
        if not access_token and refresh_token:
            try:
                # Импорты внутри функции для избежания циклических зависимостей
                from app.database import SessionLocal
                from app.auth import verify_refresh_token, create_access_token

                db = SessionLocal()
                try:
                    user = verify_refresh_token(refresh_token, db)
                    if user:
                        new_access_token = create_access_token(data={"sub": str(user.id)})

                        # Пропускаем запрос дальше по цепочке, получаем ответ
                        response = await call_next(request)

                        # Добавляем новый access_token в cookie с помощью безопасной утилиты
                        from app.secure_cookie import create_secure_cookie
                        create_secure_cookie(
                            response,
                            "access_token",
                            new_access_token,
                            expires_in=15 * 60  # 15 минут
                        )

                        return response
                finally:
                    db.close()
            except Exception as e:
                logger.debug(f"Ошибка обновления токена: {e}")

        # В остальных случаях просто передаём запрос дальше
        response = await call_next(request)
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Middleware для защиты от CSRF-атак.

    Работает следующим образом:
    - Для безопасных методов (GET, HEAD, OPTIONS) только устанавливает CSRF-токен в cookie, если его нет.
    - Для методов, изменяющих состояние (POST, PUT, DELETE, PATCH), проверяет наличие и валидность токена,
      который должен быть передан в теле запроса (в форме или JSON).
    - Поддерживает два типа токенов: простой (значение совпадает с cookie) и двойной (формат "сложный_токен:хеш").
    - Для некоторых API-эндпоинтов проверка может быть отключена (список api_endpoints_to_skip).
    - Устанавливает cookie csrf_token с флагами HttpOnly, Secure и SameSite.
    """

    async def dispatch(self, request: Request, call_next):
        # Пропускаем статику, health-проверки и WebSocket без обработки CSRF
        if (request.url.path.startswith('/static/') or
                request.url.path in ['/health', '/metrics', '/favicon.ico', '/robots.txt'] or
                request.headers.get("upgrade", "").lower() == "websocket"):
            response = await call_next(request)
            # Для исключённых путей тоже устанавливаем CSRF-токен, если его нет
            if not request.cookies.get("csrf_token"):
                is_production = os.getenv('ENVIRONMENT') == 'production'
                csrf_cookie_token = secrets.token_urlsafe(32)
                response.set_cookie(
                    key="csrf_token",
                    value=csrf_cookie_token,
                    httponly=True,
                    secure=is_production,
                    samesite='Lax' if is_production else 'None',
                    max_age=86400,  # 1 день
                    path="/"
                )
            return response

        # Получаем текущий CSRF-токен из cookie
        csrf_cookie_token = request.cookies.get("csrf_token")

        # Если cookie нет – создаём новый токен
        if not csrf_cookie_token:
            csrf_cookie_token = secrets.token_urlsafe(32)
            logger.debug(f"CSRF Middleware: Создан новый CSRF токен для cookie: {csrf_cookie_token[:10]}...")

        # Сохраняем токен в состоянии запроса для возможного использования в роутах
        request.state.csrf_token = csrf_cookie_token
        request.state._csrf_cookie_token = csrf_cookie_token

        # Для безопасных методов просто передаём запрос и устанавливаем cookie (если нужно)
        if request.method not in ["POST", "PUT", "DELETE", "PATCH"]:
            response = await call_next(request)
            if not request.cookies.get("csrf_token"):
                is_production = os.getenv('ENVIRONMENT') == 'production'
                response.set_cookie(
                    key="csrf_token",
                    value=csrf_cookie_token,
                    httponly=True,
                    secure=is_production,
                    samesite='Lax' if is_production else 'None',
                    max_age=86400,
                    path="/"
                )
            return response

        # Для изменяющих методов – начинаем проверку CSRF
        content_type = request.headers.get("content-type", "")
        submitted_token = None

        logger.debug(f"CSRF Middleware: Проверка {request.method} запроса на {request.url.path}")

        try:
            # Обработка данных формы (application/x-www-form-urlencoded или multipart/form-data)
            if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
                logger.debug(f"CSRF Middleware: Чтение формы...")

                form = await request.form()
                form_keys = list(form.keys())
                logger.debug(f"CSRF Middleware: Получено полей формы: {form_keys}")

                # Возможные имена полей для CSRF-токена
                possible_csrf_fields = ['csrf_token', 'csrf-token', '_csrf', 'csrf']

                for field in possible_csrf_fields:
                    if field in form:
                        value = form[field]
                        # Если значение пришло как список (бывает при множественных полях), берём первый элемент
                        if isinstance(value, list) and len(value) > 0:
                            submitted_token = value[0]
                        else:
                            submitted_token = value
                        logger.debug(f"CSRF Middleware: Найден токен в поле '{field}'")
                        break

                if not submitted_token and form_keys:
                    logger.warning(f"CSRF Middleware: CSRF токен не найден в форме. Доступные поля: {form_keys}")

                # Сохраняем данные формы в состоянии (для последующего использования в роутах)
                form_dict = {}
                for key in form.keys():
                    value = form.get(key)
                    if isinstance(value, list) and len(value) > 0:
                        form_dict[key] = value[0]
                    else:
                        form_dict[key] = value

                request.state._form_data = form_dict
                request.state.form_data = form

            # Обработка JSON-данных
            elif "application/json" in content_type:
                logger.debug(f"CSRF Middleware: Чтение JSON...")

                import json
                body_bytes = await request.body()
                if body_bytes:
                    try:
                        body = json.loads(body_bytes.decode('utf-8'))
                        # Ищем токен в поле 'csrf_token'
                        submitted_token = body.get("csrf_token")

                        # Сохраняем JSON-данные в состоянии
                        request.state._json_data = body
                        request.state.json_data = body
                        # Восстанавливаем тело для последующих middleware/роутов
                        request._body = body_bytes

                        logger.debug(f"CSRF Middleware: JSON данные получены")
                    except json.JSONDecodeError as e:
                        logger.error(f"CSRF Middleware: Ошибка декодирования JSON: {e}")
                else:
                    logger.debug(f"CSRF Middleware: Пустое тело JSON")

            # Для других типов контента (например, API с отдельной аутентификацией)
            else:
                logger.debug(f"CSRF Middleware: Content-Type '{content_type}' не требует CSRF проверки (для API endpoints)")
                # Список API-эндпоинтов, для которых проверка CSRF отключена
                api_endpoints_to_skip = [
                    '/api/refresh-token',
                    '/api/create_order',
                    '/api/update_order/',
                    '/api/confirm_order/',
                    '/api/booking_cancel/',
                    '/api/upload_license'
                ]

                skip_check = False
                for endpoint in api_endpoints_to_skip:
                    if request.url.path.startswith(endpoint):
                        skip_check = True
                        break

                if skip_check:
                    logger.debug(f"CSRF Middleware: Пропускаем проверку для API endpoint {request.url.path}")
                    response = await call_next(request)
                    # Устанавливаем CSRF-токен в cookie, если его нет
                    is_production = os.getenv('ENVIRONMENT') == 'production'
                    response.set_cookie(
                        key="csrf_token",
                        value=csrf_cookie_token,
                        httponly=True,
                        secure=is_production,
                        samesite='Lax' if is_production else 'None',
                        max_age=86400,
                        path="/"
                    )
                    return response

            # Если токен не найден нигде – возвращаем ошибку
            if not submitted_token:
                logger.warning(f"CSRF Middleware: CSRF токен не предоставлен для {request.method} {request.url.path}")
                return JSONResponse(
                    {
                        "detail": "CSRF токен не предоставлен",
                        "error": "csrf_token_missing",
                        "hint": "Включите csrf_token в форму или JSON данные"
                    },
                    status_code=403,
                    headers={"X-CSRF-Required": "true"}
                )

            # Определяем тип токена: простой или двойной (наличие двоеточия)
            is_double_token = ':' in submitted_token

            if is_double_token:
                # Проверка двойного токена через функцию из security_utils
                try:
                    from .security_utils import verify_double_csrf_token
                    logger.debug(f"CSRF Middleware: Проверка двойного токена")
                    csrf_valid, csrf_error = verify_double_csrf_token(submitted_token, csrf_cookie_token)

                    if not csrf_valid:
                        logger.warning(f"CSRF Middleware: Неверный двойной CSRF токен: {csrf_error}")
                        return JSONResponse(
                            {
                                "detail": f"Неверный CSRF токен: {csrf_error}",
                                "error": "csrf_token_invalid",
                                "hint": "Обновите страницу и попробуйте снова"
                            },
                            status_code=403,
                            headers={"X-CSRF-Required": "true"}
                        )

                    logger.debug(f"CSRF Middleware: Двойной CSRF токен проверен успешно")

                except ImportError as e:
                    # Если модуль security_utils не найден, используем fallback – простое сравнение
                    logger.error(f"CSRF Middleware: Ошибка импорта verify_double_csrf_token: {e}")
                    if not secrets.compare_digest(str(submitted_token), str(csrf_cookie_token)):
                        logger.warning(f"CSRF Middleware: Неверный CSRF токен (fallback проверка)")
                        return JSONResponse(
                            {
                                "detail": "Неверный CSRF токен",
                                "error": "csrf_token_invalid"
                            },
                            status_code=403,
                            headers={"X-CSRF-Required": "true"}
                        )
            else:
                # Простая проверка: токен из формы должен совпадать с токеном из cookie
                logger.debug(f"CSRF Middleware: Проверка простого токена")
                if not secrets.compare_digest(str(submitted_token), str(csrf_cookie_token)):
                    logger.warning(f"CSRF Middleware: Неверный простой CSRF токен")
                    return JSONResponse(
                        {
                            "detail": "CSRF токен недействителен",
                            "error": "csrf_token_invalid",
                            "hint": "Токен должен совпадать с тем, что в cookie"
                        },
                        status_code=403,
                        headers={"X-CSRF-Required": "true"}
                    )

                logger.debug(f"CSRF Middleware: Простой CSRF токен проверен успешно")

        except Exception as e:
            logger.error(f"CSRF Middleware: Ошибка чтения/проверки данных запроса: {e}", exc_info=True)
            return JSONResponse(
                {
                    "detail": "Ошибка проверки CSRF токена",
                    "error": "csrf_check_error"
                },
                status_code=500,
                headers={"X-CSRF-Required": "true"}
            )

        # Пропускаем запрос дальше
        response = await call_next(request)

        # На всякий случай проверяем, что ответ существует
        if response is None:
            logger.error(f"CSRF Middleware: Response is None после обработки {request.method} {request.url.path}")
            response = PlainTextResponse("Internal Server Error", status_code=500)

        # Обновляем/устанавливаем CSRF-токен в cookie
        is_production = os.getenv('ENVIRONMENT') == 'production'
        response.set_cookie(
            key="csrf_token",
            value=csrf_cookie_token,
            httponly=True,
            secure=is_production,
            samesite='Lax' if is_production else 'None',
            max_age=86400,
            path="/"
        )

        logger.debug(f"CSRF Middleware: Установлен/обновлен cookie csrf_token")
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware для установки заголовков безопасности в HTTP-ответах.

    Добавляет следующие заголовки:
    - X-Frame-Options: DENY – запрет на встраивание в iframe (защита от clickjacking)
    - X-Content-Type-Options: nosniff – запрет MIME-сниффинга
    - X-XSS-Protection: 1; mode=block – включение встроенной защиты от XSS в браузерах
    - Referrer-Policy: strict-origin-when-cross-origin – ограничение передачи Referer
    - Permissions-Policy: ограничение доступа к геолокации, микрофону, камере
    - Cross-Origin-Opener-Policy: same-origin – изоляция окна
    - Cross-Origin-Resource-Policy: same-origin – ограничение загрузки ресурсов
    - Cross-Origin-Embedder-Policy: require-corp – требование CORP для загружаемых ресурсов
    - Strict-Transport-Security (HSTS) – принудительное HTTPS (в production с preload)
    - X-Permitted-Cross-Domain-Policies: none – запрет политик cross-domain для Flash/PDF
    - Content-Security-Policy (CSP) – ограничение источников скриптов, стилей, шрифтов и т.д.
    - Feature-Policy (устаревший аналог Permissions-Policy) – также ограничивает функции
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
            is_production = os.getenv('ENVIRONMENT') == 'production'
            if is_production:
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
            else:
                response.headers["Strict-Transport-Security"] = "max-age=86400; includeSubDomains"

            response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

            # Content Security Policy (CSP) – настраивается под конкретное приложение
            # Здесь приведён пример для проекта с CDN, Google Fonts и внешним API rentsyst
            csp_policy = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net 'report-sample'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net 'report-sample'; "
                "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
                "img-src 'self' data: https: blob:; "
                "connect-src 'self' https://api.rentsyst.com https://*.rentsyst.com; "
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


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Простой middleware для ограничения частоты запросов (rate limiting) в памяти.

    Внимание: этот middleware не рекомендуется использовать вместе с WAF,
    так как WAF уже предоставляет более продвинутый rate limiting.
    Оставлен для обратной совместимости или как запасной вариант.
    """

    def __init__(self, app, limit: int = 100, window: int = 60):
        """
        :param app: ASGI-приложение
        :param limit: максимальное количество запросов за окно
        :param window: размер окна в секундах
        """
        super().__init__(app)
        self.limit = limit
        self.window = window
        self.requests = {}  # словарь: IP -> список временных меток запросов

    async def dispatch(self, request: Request, call_next):
        # Пропускаем статику, health-эндпоинты и WebSocket
        if (request.url.path.startswith('/static/') or
                request.url.path in ['/health', '/metrics', '/favicon.ico'] or
                request.headers.get("upgrade", "").lower() == "websocket"):
            return await call_next(request)

        client_ip = request.client.host if request.client else 'unknown'
        current_time = time.time()

        # Очищаем старые записи для этого IP
        if client_ip in self.requests:
            self.requests[client_ip] = [
                timestamp for timestamp in self.requests[client_ip]
                if current_time - timestamp < self.window
            ]

        # Проверяем, превышен ли лимит
        if len(self.requests.get(client_ip, [])) >= self.limit:
            return JSONResponse(
                {"detail": "Слишком много запросов"},
                status_code=429,
                headers={"Retry-After": str(self.window)}
            )

        # Добавляем текущий запрос в историю
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        self.requests[client_ip].append(current_time)

        # Пропускаем запрос дальше
        response = await call_next(request)

        if response is None:
            logger.error(f"RateLimitMiddleware получил None для {request.method} {request.url.path}")
            return PlainTextResponse("Internal Server Error", status_code=500)

        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware для логирования всех входящих HTTP-запросов и времени их обработки.
    """

    async def dispatch(self, request: Request, call_next):
        # Не логируем статику и WebSocket, чтобы не засорять логи
        if (request.url.path.startswith('/static/') or
                request.headers.get("upgrade", "").lower() == "websocket"):
            return await call_next(request)

        start_time = time.time()
        client_ip = request.client.host if request.client else 'unknown'

        logger.info(f"Входящий запрос: {request.method} {request.url.path} от {client_ip}")

        response = await call_next(request)

        if response is None:
            logger.error(f"LoggingMiddleware получил None для {request.method} {request.url.path}")
            response = PlainTextResponse("Internal Server Error", status_code=500)

        process_time = time.time() - start_time
        logger.info(
            f"Ответ: {request.method} {request.url.path} - "
            f"Статус: {response.status_code} - "
            f"Время: {process_time:.3f}s"
        )

        return response