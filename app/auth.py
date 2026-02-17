"""
Модуль аутентификации и авторизации для FastAPI-приложения.
Использует JWT с алгоритмом RS256 (асимметричное шифрование) для подписи токенов.
Ключи хранятся в PEM-файлах или генерируются автоматически при первом запуске.
Поддерживаются access, refresh и service токены.
"""

import os
import jwt
import hashlib
import secrets
import time
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .config import Config
from .database import get_db
from .models import User, RefreshToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import logging

logger = logging.getLogger(__name__)

# HTTPBearer — класс FastAPI, который извлекает токен из заголовка Authorization: Bearer <token>
security = HTTPBearer()

# Константы JWT — используются при формировании и проверке полезной нагрузки токена
JWT_ISSUER = "artifex-api"               # издатель токена (наш сервис)
JWT_AUDIENCE = "artifex-webapp"           # целевая аудитория (например, веб-приложение)
JWT_TOKEN_TYPES = {"access", "refresh", "service"}  # допустимые типы токенов


class JWTKeyManager:
    """
    Менеджер для хранения и ротации RSA-ключей.
    Ключи загружаются из PEM-файлов (private.pem, public.pem) или генерируются при отсутствии.
    Поддерживает несколько ключей для ротации: текущий ключ и предыдущие (для проверки старых токенов).
    Потокобезопасен (использует RLock).
    """

    def __init__(self):
        # _current_keys: словарь {kid: {private_key, public_key, created_at}} для активного ключа (одного или нескольких, но обычно один)
        self._current_keys = {}
        # _previous_keys: словарь для ключей, которые были текущими ранее, но уже заменены (хранятся для проверки старых токенов)
        self._previous_keys = {}
        # идентификатор текущего активного ключа
        self._current_kid = None
        # блокировка для потокобезопасного доступа к внутренним структурам
        self._lock = threading.RLock()
        # интервал ротации ключа в секундах (по умолчанию 24 часа)
        self._key_rotation_interval = 86400       # 24 часа
        # максимальное время жизни ключа (7 дней) — после этого ключ удаляется из previous
        self._max_key_age = 7 * 86400              # 7 дней
        # флаг инициализации (загружены ли ключи)
        self._initialized = False

        # Пути к файлам ключей (можно задать в конфиге)
        self.private_key_path = getattr(Config, 'PRIVATE_KEY_PATH', 'keys/private.pem')
        self.public_key_path = getattr(Config, 'PUBLIC_KEY_PATH', 'keys/public.pem')

    def _load_keys_from_files(self) -> Optional[Dict[str, Any]]:
        """Загружает ключи из PEM-файлов, если они существуют.
        Возвращает словарь с ключами: private_key, public_key, kid, created_at (время модификации файла).
        Если файлы не найдены или ошибка чтения — возвращает None.
        """
        try:
            if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
                with open(self.private_key_path, 'rb') as f:
                    private_pem = f.read().decode('utf-8')
                with open(self.public_key_path, 'rb') as f:
                    public_pem = f.read().decode('utf-8')

                # Генерируем KID на основе хеша публичного ключа (чтобы он был стабильным при повторной загрузке)
                kid = hashlib.sha256(public_pem.encode()).hexdigest()[:16]

                return {
                    'private_key': private_pem,
                    'public_key': public_pem,
                    'kid': kid,
                    'created_at': os.path.getmtime(self.private_key_path)  # время последнего изменения файла
                }
        except Exception as e:
            logger.error(f"Error loading keys from files: {e}")
        return None

    def _generate_new_key_pair(self) -> Dict[str, Any]:
        """Генерирует новую пару RSA-ключей (2048 бит) с помощью библиотеки cryptography.
        Возвращает словарь с private_key (PEM), public_key (PEM), kid (случайный 16-символьный hex), created_at (текущее время).
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        kid = secrets.token_hex(8)   # простой kid из 16 hex-символов (8 байт)

        return {
            'private_key': private_pem,
            'public_key': public_pem,
            'kid': kid,
            'created_at': time.time()
        }

    def _save_keys_to_files(self, keys: Dict[str, Any]):
        """Сохраняет ключи в PEM-файлы по указанным путям.
        Создаёт директорию, если её нет.
        """
        os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)
        with open(self.private_key_path, 'w') as f:
            f.write(keys['private_key'])
        with open(self.public_key_path, 'w') as f:
            f.write(keys['public_key'])
        logger.info(f"Keys saved to {self.private_key_path} and {self.public_key_path}")

    def initialize(self):
        """Инициализация менеджера ключей: загрузка существующих или генерация новых.
        Вызывается автоматически при первом обращении к методам, требующим ключи.
        Потокобезопасна благодаря блокировке.
        """
        with self._lock:
            if self._initialized:
                return

            keys = self._load_keys_from_files()
            if keys:
                self._current_keys[keys['kid']] = keys
                self._current_kid = keys['kid']
            else:
                keys = self._generate_new_key_pair()
                self._current_keys[keys['kid']] = keys
                self._current_kid = keys['kid']
                self._save_keys_to_files(keys)
                logger.info(f"New keys generated and saved. KID: {keys['kid']}")

            self._initialized = True

    def get_current_kid(self) -> str:
        """Возвращает идентификатор текущего активного ключа.
        При необходимости инициализирует менеджер.
        """
        with self._lock:
            if not self._initialized:
                self.initialize()
            return self._current_kid

    def get_private_key(self, kid: Optional[str] = None) -> Optional[str]:
        """Возвращает приватный ключ в PEM-формате для указанного kid.
        Если kid не указан, возвращает ключ для текущего kid.
        Если ключ не найден ни в текущих, ни в предыдущих — возвращает None.
        """
        with self._lock:
            if not self._initialized:
                self.initialize()
            if kid is None:
                kid = self._current_kid
            if kid in self._current_keys:
                return self._current_keys[kid]['private_key']
            if kid in self._previous_keys:
                return self._previous_keys[kid]['private_key']
            return None

    def get_public_key(self, kid: Optional[str] = None) -> Optional[str]:
        """Возвращает публичный ключ в PEM-формате для указанного kid.
        Аналогично get_private_key.
        """
        with self._lock:
            if not self._initialized:
                self.initialize()
            if kid is None:
                kid = self._current_kid
            if kid in self._current_keys:
                return self._current_keys[kid]['public_key']
            if kid in self._previous_keys:
                return self._previous_keys[kid]['public_key']
            return None

    def get_all_public_keys(self) -> Dict[str, str]:
        """Возвращает словарь всех известных публичных ключей (kid -> public_key PEM).
        Используется, например, для отладки или для публикации в endpoint .well-known/jwks.json.
        """
        with self._lock:
            if not self._initialized:
                self.initialize()
            all_keys = {}
            for kid, data in self._current_keys.items():
                all_keys[kid] = data['public_key']
            for kid, data in self._previous_keys.items():
                all_keys[kid] = data['public_key']
            return all_keys

    def rotate_keys(self):
        """Ротация ключей: текущий ключ уходит в previous, генерируется новый.
        Новый ключ становится текущим и сохраняется в файлы.
        Удаляет старые ключи из previous, если они превысили максимальный возраст.
        """
        with self._lock:
            try:
                new_keys = self._generate_new_key_pair()
                new_kid = new_keys['kid']

                # Если был текущий ключ, перемещаем его в предыдущие
                if self._current_kid and self._current_kid in self._current_keys:
                    self._previous_keys[self._current_kid] = self._current_keys[self._current_kid]

                # Устанавливаем новый ключ как текущий
                self._current_keys[new_kid] = new_keys
                self._current_kid = new_kid
                self._save_keys_to_files(new_keys)

                # Очистка старых ключей из previous (старше max_key_age)
                current_time = time.time()
                to_remove = []
                for kid, data in self._previous_keys.items():
                    if current_time - data['created_at'] > self._max_key_age:
                        to_remove.append(kid)
                for kid in to_remove:
                    del self._previous_keys[kid]

                logger.info(f"Keys rotated. New KID: {new_kid}")
            except Exception as e:
                logger.error(f"Error rotating keys: {e}")
                raise

    def should_rotate_keys(self) -> bool:
        """Проверяет, пора ли выполнить ротацию ключей (если возраст текущего ключа превысил интервал).
        Возвращает True, если ротация нужна.
        """
        with self._lock:
            if not self._initialized:
                return False
            if not self._current_kid or self._current_kid not in self._current_keys:
                return True
            age = time.time() - self._current_keys[self._current_kid]['created_at']
            return age > self._key_rotation_interval


# Глобальный экземпляр менеджера ключей (синглтон для всего приложения)
key_manager = JWTKeyManager()


# -------------------------------------------------------------------
# Валидация JWT claims
# -------------------------------------------------------------------

def validate_jwt_claims(payload: Dict[str, Any], token_type: str, required_scopes: Optional[List[str]] = None) -> bool:
    """Проверяет стандартные claims JWT в соответствии с требованиями приложения.
    Возвращает True, если все проверки пройдены, иначе False.
    Проверяемые поля: exp, iat, iss, aud, sub, typ, jti.
    Также проверяется соответствие типа токена, время жизни (не слишком большое), и для service токенов — наличие необходимых scopes.
    """
    # Список обязательных claims
    required_claims = {"exp", "iat", "iss", "aud", "sub", "typ", "jti"}
    missing_claims = required_claims - set(payload.keys())
    if missing_claims:
        logger.warning(f"Missing required claims: {missing_claims}")
        return False

    print("🔍 VALIDATE CLAIMS PAYLOAD:", payload)

    logger.info(f"validate_jwt_claims called with payload keys: {list(payload.keys())}")

    # Проверка типа токена
    if payload.get("typ") != token_type:
        logger.warning(f"Invalid token type. Expected: {token_type}, Got: {payload.get('typ')}")
        return False

    # Проверка издателя
    if payload.get("iss") != JWT_ISSUER:
        logger.warning(f"Invalid issuer. Expected: {JWT_ISSUER}, Got: {payload.get('iss')}")
        return False

    logger.info(f"validate_jwt_claims: full payload = {payload}")

    # Проверка аудитории (может быть строкой или списком)
    audiences = payload.get("aud", [])
    if isinstance(audiences, str):
        audiences = [audiences]
    if JWT_AUDIENCE not in audiences:
        logger.warning(f"Invalid audience. Expected: {JWT_AUDIENCE}, Got: {audiences}")
        return False

    # Проверка времени выпуска и истечения
    current_time = datetime.now(timezone.utc)
    iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)

    # Токен не может быть выпущен в будущем (допускаем рассинхронизацию часов до 60 секунд)
    if iat > current_time + timedelta(seconds=60):
        logger.warning(f"Token issued in future. iat: {iat}, current: {current_time}")
        return False

    # Проверка срока действия
    if exp < current_time:
        logger.warning(f"Token expired. exp: {exp}, current: {current_time}")
        return False

    # Проверка, что срок действия токена не превышает максимально допустимый для данного типа
    token_lifetime = exp - iat
    max_lifetime = {
        "access": timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES + 5),
        "refresh": timedelta(days=Config.REFRESH_TOKEN_EXPIRE_DAYS + 1),
        "service": timedelta(hours=24 + 1)
    }
    if token_type in max_lifetime and token_lifetime > max_lifetime[token_type]:
        logger.warning(f"Token lifetime too long for type {token_type}")
        return False

    # Для service токенов проверяем наличие всех требуемых scopes
    if token_type == "service" and required_scopes:
        token_scopes = payload.get("scopes", [])
        if not all(scope in token_scopes for scope in required_scopes):
            logger.warning(f"Missing required scopes. Required: {required_scopes}, Got: {token_scopes}")
            return False

    # Проверка формата jti (должен быть строкой из 32 символов, т.е. 16 байт в hex)
    jti = payload.get("jti", "")
    if not isinstance(jti, str) or len(jti) != 32:
        logger.warning(f"Invalid jti format: {jti}")
        return False

    return True


# -------------------------------------------------------------------
# Создание токенов
# -------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Создаёт access token (JWT) для пользователя.
    В data обычно включается 'sub' (идентификатор пользователя) и другие кастомные поля.
    Если expires_delta не указан, используется значение из Config.ACCESS_TOKEN_EXPIRE_MINUTES.
    Возвращает строку с подписанным JWT.
    """

    to_encode = data.copy()
    logger.info(f"create_access_token: payload to encode = {to_encode}")
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES)

    # Добавляем стандартные claims
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "typ": "access",
        "jti": secrets.token_hex(16),        # уникальный идентификатор токена (16 байт = 32 hex)
        "kid": key_manager.get_current_kid()  # идентификатор ключа, которым подписан токен
    })

    print("🔍 TO_ENCODE before encode:", to_encode)

    try:
        private_key = key_manager.get_private_key()
        if not private_key:
            raise ValueError("No RSA private key available")
        encoded_jwt = jwt.encode(to_encode, private_key, algorithm="RS256")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating access token: {e}")
        raise HTTPException(status_code=500, detail="Token creation failed")


def create_refresh_token(user_id: int, db: Session) -> tuple[str, datetime]:
    """Создаёт refresh token для пользователя.
    Сначала удаляет все просроченные refresh токены этого пользователя из БД.
    Генерирует случайный refresh_token (строка), сохраняет его хеш в таблицу RefreshToken вместе с датой истечения.
    Затем создаёт JWT refresh token, который содержит ссылку на запись в БД (rti).
    Возвращает кортеж (refresh_token_jwt, expires_at).
    В случае ошибки подписи JWT возвращает простой токен (без JWT) как fallback.
    """
    # Удаляем старые просроченные токены (чистка)
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.expires_at < datetime.now(timezone.utc)
    ).delete(synchronize_session=False)

    # Генерация случайного refresh токена (для хранения в БД)
    refresh_token = secrets.token_urlsafe(64)
    expires_at = datetime.now(timezone.utc) + timedelta(days=Config.REFRESH_TOKEN_EXPIRE_DAYS)

    # Создание записи в БД
    db_refresh_token = RefreshToken(
        user_id=user_id,
        token_hash=hash_token(refresh_token),
        expires_at=expires_at,
        created_at=datetime.now(timezone.utc),
        user_agent=None,
        ip_address=None
    )
    db.add(db_refresh_token)
    db.commit()
    db.refresh(db_refresh_token)

    # Формируем полезную нагрузку для JWT refresh токена
    refresh_payload = {
        "sub": str(user_id),
        "exp": expires_at,
        "iat": datetime.now(timezone.utc),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "typ": "refresh",
        "jti": secrets.token_hex(16),
        "rti": db_refresh_token.id,            # идентификатор записи в БД (Refresh Token ID)
        "kid": key_manager.get_current_kid()
    }

    try:
        private_key = key_manager.get_private_key()
        if not private_key:
            raise ValueError("No RSA private key available")
        encoded_refresh = jwt.encode(refresh_payload, private_key, algorithm="RS256")
    except Exception as e:
        logger.error(f"Error creating refresh JWT: {e}")
        encoded_refresh = refresh_token   # fallback: возвращаем сам токен без JWT-обёртки

    return encoded_refresh, expires_at


def create_service_token(service_name: str, scopes: list, expires_hours: int = 24) -> str:
    """Создаёт service token для межсервисной аутентификации.
    service_name — имя сервиса, scopes — список разрешений.
    Возвращает JWT с типом 'service'.
    """
    expire = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
    payload = {
        "sub": f"service:{service_name}",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "typ": "service",
        "scopes": scopes,
        "jti": secrets.token_hex(16),
        "kid": key_manager.get_current_kid()
    }
    try:
        private_key = key_manager.get_private_key()
        if not private_key:
            raise ValueError("No RSA private key available")
        return jwt.encode(payload, private_key, algorithm="RS256")
    except Exception as e:
        logger.error(f"Error creating service token: {e}")
        raise HTTPException(status_code=500, detail="Service token creation failed")


# -------------------------------------------------------------------
# Декодирование и верификация
# -------------------------------------------------------------------

def decode_token_with_key_rotation(token: str, token_type: Optional[str] = None,
                                   required_scopes: Optional[List[str]] = None,
                                   verify: bool = True) -> Dict[str, Any]:
    max_retries = 2
    for attempt in range(max_retries):
        try:
            # Получаем заголовок без проверки подписи, чтобы извлечь kid
            unverified_header = jwt.get_unverified_header(token)
            token_kid = unverified_header.get('kid', key_manager.get_current_kid())

            # Получаем публичный ключ по kid
            public_key = key_manager.get_public_key(token_kid)
            if not public_key:
                raise ValueError(f"No public key for kid {token_kid}")

            # Логируем попытку
            logger.info(f"decode_token attempt {attempt+1}, kid: {token_kid}")

            # Декодируем и проверяем подпись
            # Важно: не передаём параметр audience, чтобы библиотека не проверяла его автоматически
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={
                    "verify_signature": verify,
                    "verify_exp": verify,
                    "verify_iat": verify,
                    "verify_aud": False,
                    "require": ["exp", "iat", "iss", "aud", "sub", "typ", "jti"] if verify else []
                },
                leeway=30  # допуск 30 секунд на рассинхронизацию часов
            )

            logger.info(f"decode_token: payload = {payload}")

            # Если требуется полная проверка, выполняем дополнительную валидацию claims
            if verify and not validate_jwt_claims(payload, token_type, required_scopes):
                raise jwt.InvalidTokenError("Invalid JWT claims")

            return payload

        except jwt.InvalidSignatureError:
            # Если подпись недействительна, пробуем ротацию ключей и повторяем попытку
            if attempt == 0:
                logger.warning("Signature invalid, trying key rotation...")
                key_manager.rotate_keys()
                continue
            else:
                raise jwt.InvalidSignatureError("Invalid token signature after key rotation")
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise HTTPException(status_code=401, detail="Invalid token")
        except Exception as e:
            logger.error(f"Token decoding error: {e}")
            if attempt == max_retries - 1:
                raise HTTPException(status_code=500, detail="Token verification error")

    raise HTTPException(status_code=401, detail="Token verification failed after key rotation")

def decode_token(token: str, verify: bool = True) -> Dict[str, Any]:
    """Упрощённый вызов для обратной совместимости (без указания типа токена и scopes)."""
    return decode_token_with_key_rotation(token, token_type=None, required_scopes=None, verify=verify)


# -------------------------------------------------------------------
# Вспомогательные функции
# -------------------------------------------------------------------

def hash_token(token: str) -> str:
    """Возвращает SHA-256 хеш токена в hex-формате.
    Используется для безопасного хранения refresh токенов в БД.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def get_token_expiry(token: str) -> Optional[datetime]:
    """Извлекает время истечения токена (exp claim) без проверки подписи.
    Возвращает datetime в UTC или None, если поле exp отсутствует или токен невалиден.
    """
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp_timestamp = payload.get('exp')
        if exp_timestamp:
            return datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        return None
    except Exception:
        return None


def validate_token_structure(token: str) -> bool:
    """Проверяет, что строка является корректным JWT (три части, разделённые точками).
    Не проверяет подпись.
    """
    try:
        jwt.decode(token, options={"verify_signature": False})
        return True
    except jwt.InvalidTokenError:
        return False


# -------------------------------------------------------------------
# Работа с refresh токенами
# -------------------------------------------------------------------

def verify_refresh_token(refresh_token: str, db: Session) -> User:
    """Проверяет валидность refresh токена.
    Сначала пытается декодировать его как JWT и сверить с записью в БД по rti.
    Если не удаётся (старый формат или ошибка), пробует найти токен по хешу в БД (fallback).
    Возвращает объект User, если токен корректен и не отозван.
    В противном случае выбрасывает HTTPException.
    """
    try:
        # Пытаемся декодировать как JWT refresh токен
        payload = decode_token_with_key_rotation(refresh_token, token_type="refresh", verify=True)
        user_id = int(payload.get("sub"))
        rti = payload.get("rti")  # идентификатор записи в БД

        # Ищем запись в БД по id и user_id, которая не отозвана
        db_token = db.query(RefreshToken).filter(
            RefreshToken.id == rti,
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at == None
        ).first()

        if not db_token:
            raise HTTPException(status_code=401, detail="Token revoked")

        # Проверяем срок действия по БД (на всякий случай, хотя exp уже проверено в JWT)
        if db_token.expires_at < datetime.now(timezone.utc):
            db.delete(db_token)
            db.commit()
            raise HTTPException(status_code=401, detail="Refresh token expired")

    except (HTTPException, jwt.InvalidTokenError, ValueError):
        # Fallback для старых токенов (которые не были JWT, а просто случайной строкой)
        token_hash = hash_token(refresh_token)
        db_token = db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at == None
        ).first()

        if not db_token:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        user_id = db_token.user_id

        if db_token.expires_at < datetime.now(timezone.utc):
            db.delete(db_token)
            db.commit()
            raise HTTPException(status_code=401, detail="Refresh token expired")

    # Получаем пользователя по user_id
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


def revoke_refresh_token(token_id: int, db: Session):
    """Отзывает конкретный refresh токен по его id (устанавливает revoked_at)."""
    db_token = db.query(RefreshToken).filter(
        RefreshToken.id == token_id,
        RefreshToken.revoked_at == None
    ).first()
    if db_token:
        db_token.revoked_at = datetime.now(timezone.utc)
        db.commit()


def revoke_all_user_refresh_tokens(user_id: int, db: Session):
    """Отзывает все активные refresh токены пользователя."""
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at == None
    ).update({"revoked_at": datetime.now(timezone.utc)})
    db.commit()


# -------------------------------------------------------------------
# Зависимости FastAPI
# -------------------------------------------------------------------

from fastapi import Request  # Добавьте этот импорт в начало файла

async def get_current_user(
        request: Request,
        db: Session = Depends(get_db)
) -> User:
    try:
        token = request.cookies.get("access_token")

        # Если токен пришёл как байты, преобразуем в строку
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            logger.info(f"get_current_user: token decoded from bytes")

        if not token:
            logger.warning("No access token in cookies")
            raise HTTPException(status_code=401, detail="Not authenticated")

        token = token.strip()

        # Дополнительная проверка: если токен всё ещё начинается с "b'" и заканчивается "'", удаляем
        # Это может случиться, если cookie была установлена как repr(bytes)
        if token.startswith("b'") and token.endswith("'"):
            token = token[2:-1]
            logger.info("get_current_user: stripped b' literal from token")

        logger.info(f"Token from cookie (first 50 chars): {token[:50]}...")

        payload = decode_token_with_key_rotation(token, token_type="access", verify=True)

        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token missing user id")

        try:
            user_id_int = int(user_id)
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid user id format")

        user = db.query(User).filter(User.id == user_id_int).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Account locked")

        logger.info(f"User authenticated: {user.username} (ID: {user.id})")
        return user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in get_current_user: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Authentication error")

async def get_current_user_optional(
        request: Request,
        db: Session = Depends(get_db)
) -> Optional[User]:
    """FastAPI dependency для получения текущего пользователя из cookie (опционально)"""
    try:
        token = request.cookies.get("access_token")
        if not token:
            return None

        return await get_current_user(request, db)
    except HTTPException:
        return None
    except Exception:
        return None

async def get_current_admin_user(
        current_user: User = Depends(get_current_user)
) -> User:
    """
    Возвращает текущего пользователя, если он является администратором (учителем).
    Иначе выбрасывает исключение 403.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав. Требуется роль учителя."
        )
    return current_user

def verify_service_token(token: str, required_scopes: Optional[List[str]] = None) -> dict:
    """Проверяет service token (используется вне контекста FastAPI, например, в middleware).
    Возвращает payload токена или выбрасывает HTTPException при ошибке.
    """
    try:
        return decode_token_with_key_rotation(token, token_type="service", required_scopes=required_scopes, verify=True)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Service token verification error: {e}")
        raise HTTPException(status_code=401, detail="Service token verification failed")