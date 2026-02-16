import os
from dotenv import load_dotenv
from typing import Optional, Dict, Any


class Config:
    ENVIRONMENT = os.getenv('IS_PRODUCTION')
    @classmethod
    def get_smtp_config(cls) -> Dict[str, Any]:
        return {
            'server': cls._get_secret('smtp', 'SMTP_SERVER', 'smtp.gmail.com'),
            'port': int(cls._get_secret('smtp', 'SMTP_PORT', '587')),
            'username': cls._get_secret('smtp', 'SMTP_USERNAME'),
            'password': cls._get_secret('smtp', 'SMTP_PASSWORD'),
            'use_tls': True
        }
    SECRET_KEY = os.getenv('SECRET_KEY')

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    SECRETS_DIR = os.path.join(BASE_DIR, 'secrets')

    ACCESS_TOKEN_EXPIRE_MINUTES = 60
    REFRESH_TOKEN_EXPIRE_DAYS = 80

    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    SECURE_COOKIES = ENVIRONMENT == 'production'
    SESSION_COOKIE_SECURE = SECURE_COOKIES
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'