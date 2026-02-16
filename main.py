"""
Главный модуль FastAPI-приложения "Artifex - Дневник".
Выполняет настройку приложения, подключение статических файлов,
маршрутов (роутов) и инициализацию Web Application Firewall (WAF).
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.routes import router
from app.waf import setup_waf, DEFAULT_WAF_CONFIG
import logging
from app.auth import key_manager
from app.routes_diary import router as diary_router

# Создаём экземпляр FastAPI с заголовком приложения
app = FastAPI(title="Artifex - Дневник")

# Монтируем директорию со статическими файлами (CSS, JS, изображения)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Подключаем основной роутер с эндпоинтами приложения
app.include_router(router)
app.include_router(diary_router)

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
    'log_level': 'INFO'
}

# Инициализация WAF
waf_engine = setup_waf(app, waf_config)

key_manager.initialize()

if key_manager.should_rotate_keys():
    key_manager.rotate_keys()