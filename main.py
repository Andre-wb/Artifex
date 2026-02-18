"""
Главный модуль FastAPI-приложения "Artifex - Дневник".
Выполняет настройку приложения, подключение статических файлов,
маршрутов (роутов) и инициализацию Web Application Firewall (WAF).
"""

from fastapi.exception_handlers import http_exception_handler
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from app.waf import setup_waf, DEFAULT_WAF_CONFIG
import logging
import asyncio
from app.auth import key_manager
from app.routes_diary import router as diary_router
from fastapi.templating import Jinja2Templates
from app.routes_gamification import router as gamification_router
from app.routes_chat import router as chat_router
from app.routes_mood import router as mood_router
from app.routes_academic import router as academic_router
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from app.load_analyzer import run_load_analysis_for_all_users
from app.database import SessionLocal
from app.routes_warnings import router as warnings_router
from app.routes_reminder import router as reminder_router
from app.routes_auth import router as auth_router
from app.routes_profile import router as profile_router
from app.routes_diary_api import router as diary_api_router
from app.routes_ai import router as ai_router
from app.routes_youtube import router as materials_router
from apscheduler.triggers.interval import IntervalTrigger
from app.routes_pages import router as pages_router

# Создаём экземпляр FastAPI с заголовком приложения
app = FastAPI(title="Artifex - Дневник")

# Монтируем директорию со статическими файлами (CSS, JS, изображения)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

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

# Создаем планировщик
scheduler = AsyncIOScheduler()

async def scheduled_load_analysis():
    """Запланированная задача для анализа нагрузки всех пользователей (неблокирующая)"""
    logger.info("Запуск запланированного анализа нагрузки для всех пользователей")
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _run_load_analysis_sync)
    logger.info("Анализ нагрузки успешно завершен")

def _run_load_analysis_sync():
    """Синхронная обёртка, выполняющая анализ в отдельном потоке"""
    db = SessionLocal()
    try:
        run_load_analysis_for_all_users(db)
    except Exception as e:
        logger.error(f"Ошибка при выполнении анализа нагрузки: {e}")
    finally:
        db.close()

# Инициализация при запуске приложения
@app.on_event("startup")
async def startup_event():
    """Действия при запуске приложения"""
    logger.info("Запуск приложения Artifex - Дневник")

    # Добавляем задачу в планировщик
    scheduler.add_job(
        scheduled_load_analysis,
        IntervalTrigger(minutes=30),
        id="load_analysis_30min",
        replace_existing=True
    )

    # Запускаем планировщик
    scheduler.start()
    logger.info("Планировщик задач запущен. Ежедневный анализ запланирован на 20:00")

    # Инициализация WAF (раскомментируйте если нужно)
    # waf_engine = setup_waf(app, waf_config)

    # Инициализация ключей
    key_manager.initialize()
    if key_manager.should_rotate_keys():
        key_manager.rotate_keys()

    logger.info("Приложение успешно запущено")

@app.on_event("shutdown")
async def shutdown_event():
    """Действия при остановке приложения"""
    logger.info("Остановка приложения Artifex - Дневник")

    # Останавливаем планировщик
    scheduler.shutdown()
    logger.info("Планировщик задач остановлен")

# Подключаем все роутеры
app.include_router(diary_router)
app.include_router(chat_router)
app.include_router(mood_router)
app.include_router(academic_router)
app.include_router(warnings_router)
app.include_router(reminder_router)
app.include_router(gamification_router)
app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(diary_api_router)
app.include_router(ai_router)
app.include_router(materials_router)
app.include_router(pages_router)

templates = Jinja2Templates(directory="templates")
app.state.templates = templates

@app.exception_handler(HTTPException)
async def unauthorized_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        return templates.TemplateResponse(
            "not_authenticated.html",
            {"request": request},
            status_code=401
        )
    return await http_exception_handler(request, exc)