"""
Модуль аутентификации и авторизации для FastAPI-приложения.

Использует JWT (JSON Web Tokens) с алгоритмом HS256 (симметричное шифрование).
Поддерживает:
- Access токены (короткоживущие) для доступа к защищённым ресурсам
- Refresh токены (долгоживущие) для обновления access токенов, хранятся в БД
- Service токены для межсервисной аутентификации
- Валидацию стандартных JWT claims (iss, aud, exp, iat, sub, typ, jti)
- Работу с refresh токенами: создание, верификация, отзыв
"""

import os
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .config import Config  # импортируем объект конфигурации (должен содержать SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS)
from .database import get_db
from .models import User, RefreshToken

import logging

logger = logging.getLogger(__name__)

# Объект для извлечения токена из заголовка Authorization: Bearer <token>
security = HTTPBearer()

# Константы для JWT
JWT_ISSUER = "borisrent-api"          # издатель токена
JWT_AUDIENCE = "borisrent-webapp"     # аудитория токена (клиент, которому предназначен токен)
JWT_TOKEN_TYPES = {"access", "refresh", "service"}  # допустимые типы токенов

# -------------------------------------------------------------------
# Управление секретным ключом для HS256
# -------------------------------------------------------------------

def get_jwt_secret() -> str:
    """
    Возвращает секретный ключ для подписи JWT.
    Ключ берётся из конфигурации (config.SECRET_KEY).
    Убедитесь, что SECRET_KEY достаточно длинный и сложный (например, минимум 32 символа).
    В production должен храниться в переменных окружения или секретном хранилище.
    """
    secret = config.SECRET_KEY
    if not secret:
        logger.critical("SECRET_KEY не задан! JWT подпись невозможна.")
        raise ValueError("JWT secret key is missing")
    return secret


# -------------------------------------------------------------------
# Валидация стандартных JWT claims
# -------------------------------------------------------------------

def validate_jwt_claims(payload: Dict[str, Any], token_type: str, required_scopes: Optional[List[str]] = None) -> bool:
    """
    Проверяет корректность стандартных полей (claims) JWT.

    Аргументы:
        payload: декодированный payload токена
        token_type: ожидаемый тип токена ('access', 'refresh', 'service')
        required_scopes: список обязательных разрешений (только для service токенов)

    Возвращает:
        True если все проверки пройдены, иначе False.
    """
    # Проверка наличия обязательных полей
    required_claims = {"exp", "iat", "iss", "aud", "sub", "typ", "jti"}
    missing_claims = required_claims - set(payload.keys())
    if missing_claims:
        logger.warning(f"Missing required claims: {missing_claims}")
        return False

    # Проверка типа токена
    if payload.get("typ") != token_type:
        logger.warning(f"Invalid token type. Expected: {token_type}, Got: {payload.get('typ')}")
        return False

    # Проверка издателя
    if payload.get("iss") != JWT_ISSUER:
        logger.warning(f"Invalid issuer. Expected: {JWT_ISSUER}, Got: {payload.get('iss')}")
        return False

    # Проверка аудитории (может быть строкой или списком)
    audiences = payload.get("aud", [])
    if isinstance(audiences, str):
        audiences = [audiences]
    if JWT_AUDIENCE not in audiences:
        logger.warning(f"Invalid audience. Expected: {JWT_AUDIENCE}, Got: {audiences}")
        return False

    # Проверка временных меток (с учётом возможного рассинхрона часов)
    current_time = datetime.now(timezone.utc)
    iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)

    # Токен не должен быть выдан в будущем (допуск 60 секунд)
    if iat > current_time + timedelta(seconds=60):
        logger.warning(f"Token issued in future. iat: {iat}, current: {current_time}")
        return False

    # Токен не должен быть просрочен
    if exp < current_time:
        logger.warning(f"Token expired. exp: {exp}, current: {current_time}")
        return False

    # Проверка максимального времени жизни токена (защита от неверной генерации)
    token_lifetime = exp - iat
    max_lifetime = {
        "access": timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES + 5),   # +5 минут допуск
        "refresh": timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS + 1),      # +1 день допуск
        "service": timedelta(hours=24 + 1)                                    # +1 час допуск
    }
    if token_type in max_lifetime and token_lifetime > max_lifetime[token_type]:
        logger.warning(f"Token lifetime too long for type {token_type}. Max: {max_lifetime[token_type]}, Got: {token_lifetime}")
        return False

    # Проверка разрешений (scopes) для service токенов
    if token_type == "service" and required_scopes:
        token_scopes = payload.get("scopes", [])
        if not all(scope in token_scopes for scope in required_scopes):
            logger.warning(f"Missing required scopes. Required: {required_scopes}, Got: {token_scopes}")
            return False

    # Проверка формата jti (должен быть 16 байт в hex = 32 символа)
    jti = payload.get("jti", "")
    if not isinstance(jti, str) or len(jti) != 32:
        logger.warning(f"Invalid jti format: {jti}")
        return False

    return True


# -------------------------------------------------------------------
# Создание токенов
# -------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Создаёт access токен (короткоживущий).

    Аргументы:
        data: словарь с данными для включения в payload (обычно {'sub': user_id})
        expires_delta: время жизни токена (если не указано, берётся из config.ACCESS_TOKEN_EXPIRE_MINUTES)

    Возвращает:
        JWT строку, подписанную HS256.
    """
    to_encode = data.copy()

    # Устанавливаем время истечения
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)

    # Добавляем стандартные claims
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "typ": "access",
        "jti": secrets.token_hex(16),      # уникальный идентификатор токена
    })

    try:
        secret = get_jwt_secret()
        encoded_jwt = jwt.encode(to_encode, secret, algorithm="HS256")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating access token: {e}")
        raise HTTPException(status_code=500, detail="Token creation failed")


def create_refresh_token(user_id: int, db: Session) -> tuple[str, datetime]:
    """
    Создаёт refresh токен (долгоживущий) и сохраняет его хеш в БД.

    Аргументы:
        user_id: идентификатор пользователя
        db: сессия SQLAlchemy

    Возвращает:
        Кортеж (refresh_token_string, expires_at)
    """
    # Удаляем все просроченные refresh токены для этого пользователя
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.expires_at < datetime.now(timezone.utc)
    ).delete(synchronize_session=False)

    # Генерируем случайный токен (будет использоваться как bearer токен)
    refresh_token = secrets.token_urlsafe(64)
    expires_at = datetime.now(timezone.utc) + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)

    # Сохраняем хеш токена в БД (на случай компрометации БД)
    db_refresh_token = RefreshToken(
        user_id=user_id,
        token_hash=hash_token(refresh_token),
        expires_at=expires_at,
        created_at=datetime.now(timezone.utc),
        user_agent=None,      # можно заполнить позже, если передавать request
        ip_address=None       # можно заполнить позже
    )
    db.add(db_refresh_token)
    db.commit()
    db.refresh(db_refresh_token)

    # Создаём JWT refresh токен (он содержит ссылку на запись в БД через rti)
    refresh_payload = {
        "sub": str(user_id),
        "exp": expires_at,
        "iat": datetime.now(timezone.utc),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "typ": "refresh",
        "jti": secrets.token_hex(16),
        "rti": db_refresh_token.id,          # идентификатор записи в таблице refresh_tokens
    }

    try:
        secret = get_jwt_secret()
        encoded_refresh = jwt.encode(refresh_payload, secret, algorithm="HS256")
    except Exception as e:
        logger.error(f"Error creating refresh JWT: {e}")
        # В случае ошибки JWT возвращаем просто случайный токен (fallback)
        encoded_refresh = refresh_token

    return encoded_refresh, expires_at


def create_service_token(service_name: str, scopes: list, expires_hours: int = 24) -> str:
    """
    Создаёт токен для межсервисной аутентификации.

    Аргументы:
        service_name: имя сервиса (будет использовано в поле sub)
        scopes: список разрешений (например, ['read:users', 'write:bookings'])
        expires_hours: время жизни в часах

    Возвращает:
        JWT строку.
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
    }

    try:
        secret = get_jwt_secret()
        return jwt.encode(payload, secret, algorithm="HS256")
    except Exception as e:
        logger.error(f"Error creating service token: {e}")
        raise HTTPException(status_code=500, detail="Service token creation failed")


# -------------------------------------------------------------------
# Декодирование и верификация токенов
# -------------------------------------------------------------------

def decode_token(token: str, token_type: Optional[str] = None,
                 required_scopes: Optional[List[str]] = None,
                 verify: bool = True) -> Dict[str, Any]:
    """
    Декодирует и проверяет JWT токен.

    Аргументы:
        token: строка JWT
        token_type: ожидаемый тип токена (если указан, проверяется соответствие)
        required_scopes: список обязательных разрешений (только для service токенов)
        verify: если True, выполняет полную проверку подписи и claims

    Возвращает:
        payload токена в виде словаря.

    Исключения:
        HTTPException с кодом 401 при невалидном токене.
    """
    try:
        secret = get_jwt_secret()
        # Декодируем с проверкой подписи и временных меток
        options = {
            "verify_signature": verify,
            "verify_exp": verify,
            "verify_iat": verify,
            "require": ["exp", "iat", "iss", "aud", "sub", "typ", "jti"] if verify else []
        }
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options=options,
            leeway=30  # 30 секунд допуска для рассинхрона часов
        )

        # Если запрошена полная проверка, выполняем дополнительную валидацию claims
        if verify:
            if not validate_jwt_claims(payload, token_type, required_scopes):
                raise jwt.InvalidTokenError("Invalid JWT claims")

        return payload

    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Token decoding error: {e}")
        raise HTTPException(status_code=500, detail="Token verification error")


# -------------------------------------------------------------------
# Вспомогательные функции
# -------------------------------------------------------------------

def hash_token(token: str) -> str:
    """Возвращает SHA256 хеш токена для безопасного хранения в БД."""
    return hashlib.sha256(token.encode()).hexdigest()


def get_token_expiry(token: str) -> Optional[datetime]:
    """
    Извлекает время истечения токена без проверки подписи.
    Полезно для отладки или проверки срока жизни.
    """
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp_timestamp = payload.get('exp')
        if exp_timestamp:
            return datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        return None
    except Exception as e:
        logger.error(f"Error getting token expiry: {e}")
        return None


def validate_token_structure(token: str) -> bool:
    """
    Проверяет, что токен имеет корректную структуру JWT (без проверки подписи).
    """
    try:
        jwt.decode(token, options={"verify_signature": False})
        return True
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token structure: {e}")
        return False
    except Exception as e:
        logger.error(f"Token structure validation error: {e}")
        return False


# -------------------------------------------------------------------
# Работа с refresh токенами (БД)
# -------------------------------------------------------------------

def verify_refresh_token(refresh_token: str, db: Session) -> User:
    """
    Проверяет refresh токен и возвращает пользователя.

    Аргументы:
        refresh_token: строка refresh токена (может быть как JWT, так и простым токеном)
        db: сессия SQLAlchemy

    Возвращает:
        Объект User, если токен валиден.

    Исключения:
        HTTPException 401 при невалидном токене.
    """
    try:
        # Сначала пытаемся декодировать как JWT (новый формат)
        payload = decode_token(refresh_token, token_type="refresh", verify=True)
        user_id = int(payload.get("sub"))
        rti = payload.get("rti")   # идентификатор записи в таблице refresh_tokens

        # Ищем запись в БД по rti и user_id, которая не отозвана
        db_token = db.query(RefreshToken).filter(
            RefreshToken.id == rti,
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at == None
        ).first()

        if not db_token:
            logger.warning(f"Refresh token record not found or revoked for user {user_id}")
            raise HTTPException(status_code=401, detail="Token revoked")

        # Проверяем срок действия записи
        if db_token.expires_at < datetime.now(timezone.utc):
            db.delete(db_token)
            db.commit()
            raise HTTPException(status_code=401, detail="Refresh token expired")

    except (HTTPException, jwt.InvalidTokenError, ValueError):
        # Если не удалось декодировать как JWT, пробуем старый формат (простой токен по хешу)
        token_hash = hash_token(refresh_token)
        db_token = db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at == None
        ).first()

        if not db_token:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        user_id = db_token.user_id

        # Проверка срока действия
        if db_token.expires_at < datetime.now(timezone.utc):
            db.delete(db_token)
            db.commit()
            raise HTTPException(status_code=401, detail="Refresh token expired")

    # Получаем пользователя
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        logger.error(f"User not found for refresh token: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    return user


def revoke_refresh_token(token_id: int, db: Session):
    """Отзывает конкретный refresh токен по его ID в БД."""
    db_token = db.query(RefreshToken).filter(
        RefreshToken.id == token_id,
        RefreshToken.revoked_at == None
    ).first()
    if db_token:
        db_token.revoked_at = datetime.now(timezone.utc)
        db.commit()
        logger.info(f"Revoked refresh token {token_id}")


def revoke_all_user_refresh_tokens(user_id: int, db: Session):
    """Отзывает все активные refresh токены пользователя."""
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at == None
    ).update({"revoked_at": datetime.now(timezone.utc)})
    db.commit()
    logger.info(f"Revoked all refresh tokens for user {user_id}")


# -------------------------------------------------------------------
# Зависимости (dependencies) для FastAPI
# -------------------------------------------------------------------

def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db)
) -> User:
    """
    Dependency для получения текущего аутентифицированного пользователя.
    Используется в защищённых эндпоинтах.

    Ожидает access токен в заголовке Authorization: Bearer <token>.
    Возвращает объект User или выбрасывает HTTPException.
    """
    try:
        token = credentials.credentials
        payload = decode_token(token, token_type="access", verify=True)

        user_id = payload.get("sub")
        if not user_id:
            logger.warning("Token missing 'sub' claim")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Токен не содержит идентификатора пользователя"
            )

        try:
            user_id_int = int(user_id)
        except ValueError:
            logger.warning(f"Invalid user_id format in token: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный формат идентификатора пользователя"
            )

        user = db.query(User).filter(User.id == user_id_int).first()
        if not user:
            logger.warning(f"User not found for id: {user_id_int}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Пользователь не найден"
            )

        # Дополнительная проверка блокировки аккаунта (если есть поле locked_until)
        if hasattr(user, 'locked_until') and user.locked_until and user.locked_until > datetime.now(timezone.utc):
            logger.warning(f"User {user_id_int} is locked until {user.locked_until}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Аккаунт временно заблокирован"
            )

        logger.debug(f"Authenticated user: {user.username} (ID: {user.id})")
        return user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in get_current_user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка при проверке аутентификации"
        )


def get_current_user_optional(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
        db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Dependency для опциональной аутентификации.
    Возвращает пользователя, если токен валиден, иначе None.
    Полезна для эндпоинтов, которые могут работать как с авторизованными, так и с анонимными пользователями.
    """
    try:
        if credentials:
            return get_current_user(credentials, db)
    except HTTPException as e:
        # Возвращаем None при ошибках аутентификации (401, 403), остальные пробрасываем дальше
        if e.status_code in (401, 403):
            return None
        raise
    return None


# -------------------------------------------------------------------
# Проверка service токенов (для внутренних вызовов)
# -------------------------------------------------------------------

def verify_service_token(token: str, required_scopes: Optional[List[str]] = None) -> dict:
    """
    Проверяет service токен и возвращает его payload.
    Используется для аутентификации между микросервисами.
    """
    try:
        payload = decode_token(token, token_type="service", required_scopes=required_scopes, verify=True)
        return payload
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Service token verification error: {e}")
        raise HTTPException(status_code=401, detail="Service token verification failed")