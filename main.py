"""
Главный модуль FastAPI-приложения "Artifex - Дневник".
Выполняет настройку приложения, подключение статических файлов,
маршрутов (роутов) и инициализацию Web Application Firewall (WAF).
"""

from fastapi.exception_handlers import http_exception_handler
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from app.routes import router
from app.waf import setup_waf, DEFAULT_WAF_CONFIG
import logging
from app.auth import key_manager
from app.routes_diary import router as diary_router
from fastapi.templating import Jinja2Templates
from app.routes_gamification import router as gamification_router
from app.routes_chat import router as chat_router
from app.routes_mood import router as mood_router
from app.routes_academic import router as academic_router

# Создаём экземпляр FastAPI с заголовком приложения
app = FastAPI(title="Artifex - Дневник")

# Монтируем директорию со статическими файлами (CSS, JS, изображения)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Подключаем основной роутер с эндпоинтами приложения
app.include_router(router)
app.include_router(diary_router)
app.include_router(chat_router)
app.include_router(mood_router)
app.include_router(academic_router)

templates = Jinja2Templates(directory="templates")
app.state.templates = templates

# Настройка базового логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Конфигурация WAF (Web Application Firewall)
waf_config = {
    'rate_limit_requests': 100,
    'rate_limit_window': 60,
    'block_duration': 3600,
    'max_content_length': 10 * 1024 * 1024,
    'whitelist_ips': ['127.0.0.1', '000.000.00.00'],
    'enable_captcha': True,
    'log_level': 'INFO',
    'safe_params': ['csrf_token', '_csrf', 'csrfmiddlewaretoken', 'authenticity_token']
}

# Инициализация WAF
# waf_engine = setup_waf(app, waf_config)

key_manager.initialize()

if key_manager.should_rotate_keys():
    key_manager.rotate_keys()

@app.exception_handler(HTTPException)
async def unauthorized_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return templates.TemplateResponse(
            "not_authenticated.html",
            {"request": request},
            status_code=401
        )
    return await http_exception_handler(request, exc)

app.include_router(router)
app.include_router(diary_router)
app.include_router(gamification_router)