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


# Создаём экземпляр FastAPI с заголовком приложения
app = FastAPI(title="Artifex - Дневник")

# Монтируем директорию со статическими файлами (CSS, JS, изображения)
# Все запросы, начинающиеся с /static, будут обслуживаться из папки app/static
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Подключаем основной роутер с эндпоинтами приложения
# Роутер определён в модуле app.routes
app.include_router(router)

# Настройка базового логирования
# Уровень INFO, формат: время - имя логгера - уровень - сообщение
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Конфигурация WAF (Web Application Firewall)
# Здесь задаются параметры защиты приложения
waf_config = {
    'rate_limit_requests': 100,          # Максимальное число запросов от одного IP в окне
    'rate_limit_window': 60,              # Окно rate limiting в секундах
    'block_duration': 3600,                # Длительность временной блокировки IP (1 час)
    'max_content_length': 10 * 1024 * 1024,  # Максимальный размер тела запроса (10 МБ)
    'whitelist_ips': ['127.0.0.1', '000.000.00.00'],  # IP-адреса, исключённые из блокировок (замените на свои)
    'enable_captcha': True,                # Включение CAPTCHA при подозрительной активности
    'log_level': 'INFO'                     # Уровень логирования WAF
}

# Инициализация WAF: middleware и роуты управления подключаются к приложению
# Функция setup_waf возвращает экземпляр WAFEngine для дальнейшего использования (опционально)
waf_engine = setup_waf(app, waf_config)

key_manager.initialize()

if key_manager.should_rotate_keys():
    key_manager.rotate_keys()