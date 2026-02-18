"""
Модуль конфигурации приложения.
Загружает переменные окружения из .env файла и предоставляет настройки.
"""

import os
from dotenv import load_dotenv
from typing import Dict, Any

# Загружаем переменные окружения из файла .env (если он существует)
load_dotenv()


class Config:
    # Режим окружения: 'production' или 'development' (по умолчанию development)
    ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')

    # Секретный ключ для подписей (JWT, CSRF, etc.)
    # В production обязательно должен быть задан через переменную окружения
    SECRET_KEY = os.getenv('SECRET_KEY')

    # Базовая директория проекта (для формирования путей)
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    SECRETS_DIR = os.path.join(BASE_DIR, 'secrets')

    # Настройки JWT токенов
    ACCESS_TOKEN_EXPIRE_MINUTES = 60
    REFRESH_TOKEN_EXPIRE_DAYS = 80

    # Настройки загрузки файлов
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    # Настройки безопасных cookie
    SECURE_COOKIES = ENVIRONMENT == 'production'
    SESSION_COOKIE_SECURE = SECURE_COOKIES
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    @classmethod
    def is_production(cls) -> bool:
        """Возвращает True, если приложение запущено в production-режиме."""
        return cls.ENVIRONMENT == 'production'

    @classmethod
    def get_smtp_config(cls) -> Dict[str, Any]:
        """
        Возвращает конфигурацию SMTP для отправки писем.
        Данные берутся из переменных окружения или используются значения по умолчанию.
        """
        return {
            'SMTP_SERVER': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
            'SMTP_PORT': int(os.getenv('SMTP_PORT', '587')),
            'SMTP_USERNAME': os.getenv('SMTP_USERNAME'),
            'SMTP_PASSWORD': os.getenv('SMTP_PASSWORD'),
            'use_tls': True
        }

    @classmethod
    def get_database_url(cls):
        db_path = os.path.join(cls.BASE_DIR, 'app.db')
        return f"sqlite:///{db_path}"

    PRIVATE_KEY_PATH = 'secrets/private.pem'
    PUBLIC_KEY_PATH = 'secrets/public.pem'

    API_KEY = os.getenv("GROQ_API_KEY")

    YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")

    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
    TELEGRAM_BOT_USERNAME = os.getenv('TELEGRAM_BOT_USERNAME')