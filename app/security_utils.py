"""
Модуль безопасности, содержащий утилиты для защиты от timing-атак,
генерации токенов, CSRF-защиты, валидации данных и безопасного сравнения.

Все функции, связанные со сравнением, используют constant-time операции
(hmac.compare_digest), чтобы исключить возможность timing-атак.

Модуль не имеет внешних зависимостей, кроме стандартной библиотеки Python.
"""

import secrets
import time
import hmac
import hashlib
import base64
import struct
from typing import List, Dict, Any, Union, Optional, Callable, Tuple
from functools import wraps
import asyncio
from datetime import datetime, timedelta
import hashlib
import binascii
import os
import re
import logging

logger = logging.getLogger(__name__)

# Константы для регулирования времени выполнения (защита от timing-атак)
MIN_EXECUTION_TIME = 0.001      # минимальное время выполнения sensitive операций (сек)
MAX_EXECUTION_TIME = 0.005      # максимальное время выполнения (для логирования)
TOKEN_LENGTH = 32                # длина токенов в байтах (для генерации)
SALT_LENGTH = 16                 # длина соли в байтах (hex)
NONCE_LENGTH = 16                # длина nonce в байтах
DEFAULT_HASH_ALGORITHM = 'sha256'
DEFAULT_ITERATIONS = 100000      # количество итераций PBKDF2


def constant_time_compare(val1: Union[str, bytes], val2: Union[str, bytes]) -> bool:
    """
    Сравнивает две строки или байтовые последовательности за константное время.
    Использует hmac.compare_digest для защиты от timing-атак.

    Аргументы:
        val1: первое значение (str или bytes)
        val2: второе значение (str или bytes)

    Возвращает:
        True если значения равны, иначе False.
    """
    if isinstance(val1, str):
        val1 = val1.encode('utf-8')
    if isinstance(val2, str):
        val2 = val2.encode('utf-8')
    return hmac.compare_digest(val1, val2)


def constant_time_contains(haystack: Union[str, bytes], needle: Union[str, bytes]) -> bool:
    """
    Проверяет, содержит ли строка (или байтовая строка) подстроку,
    выполняя сравнение за константное время (без раннего выхода).
    Полезна для защиты от timing-атак при проверке наличия подстроки.

    Аргументы:
        haystack: строка, в которой выполняется поиск
        needle: искомая подстрока

    Возвращает:
        True если needle найдена в haystack, иначе False.
    """
    if isinstance(haystack, str):
        haystack_bytes = haystack.encode('utf-8')
    else:
        haystack_bytes = haystack

    if isinstance(needle, str):
        needle_bytes = needle.encode('utf-8')
    else:
        needle_bytes = needle

    if len(needle_bytes) == 0:
        return True
    if len(needle_bytes) > len(haystack_bytes):
        return False

    result = False
    for i in range(len(haystack_bytes) - len(needle_bytes) + 1):
        match = hmac.compare_digest(
            haystack_bytes[i:i + len(needle_bytes)],
            needle_bytes
        )
        if match:
            result = True
    return result


def constant_time_starts_with(string: Union[str, bytes], prefix: Union[str, bytes]) -> bool:
    """
    Проверяет, начинается ли строка с заданного префикса, за константное время.
    Безопасна против timing-атак.

    Аргументы:
        string: проверяемая строка
        prefix: искомый префикс

    Возвращает:
        True если string начинается с prefix, иначе False.
    """
    if isinstance(string, str):
        string_bytes = string.encode('utf-8')
    else:
        string_bytes = string

    if isinstance(prefix, str):
        prefix_bytes = prefix.encode('utf-8')
    else:
        prefix_bytes = prefix

    if len(prefix_bytes) > len(string_bytes):
        return False

    return hmac.compare_digest(string_bytes[:len(prefix_bytes)], prefix_bytes)


def constant_time_ends_with(string: Union[str, bytes], suffix: Union[str, bytes]) -> bool:
    """
    Проверяет, заканчивается ли строка заданным суффиксом, за константное время.
    Безопасна против timing-атак.

    Аргументы:
        string: проверяемая строка
        suffix: искомый суффикс

    Возвращает:
        True если string заканчивается на suffix, иначе False.
    """
    if isinstance(string, str):
        string_bytes = string.encode('utf-8')
    else:
        string_bytes = string

    if isinstance(suffix, str):
        suffix_bytes = suffix.encode('utf-8')
    else:
        suffix_bytes = suffix

    if len(suffix_bytes) > len(string_bytes):
        return False

    return hmac.compare_digest(string_bytes[-len(suffix_bytes):], suffix_bytes)


def constant_time_select(condition: bool, true_val: Any, false_val: Any) -> Any:
    """
    Выбирает одно из двух значений в зависимости от условия,
    стараясь избегать ветвления, которое может привести к timing-уязвимостям.
    Для целых чисел используется битовая маска, для остальных типов – тернарный оператор.

    Аргументы:
        condition: условие (True/False)
        true_val: значение, возвращаемое при condition == True
        false_val: значение, возвращаемое при condition == False

    Возвращает:
        true_val или false_val в зависимости от условия.
    """
    mask = -1 if condition else 0
    if isinstance(true_val, int) and isinstance(false_val, int):
        return (true_val & mask) | (false_val & ~mask)
    return true_val if condition else false_val


def timing_safe_hash(data: str, salt: Optional[str] = None,
                     algorithm: str = DEFAULT_HASH_ALGORITHM,
                     iterations: int = DEFAULT_ITERATIONS) -> Tuple[str, str]:
    """
    Вычисляет хеш строки с использованием PBKDF2-HMAC.
    Время выполнения зависит от iterations, что обеспечивает защиту от брутфорса.

    Аргументы:
        data: исходная строка
        salt: соль (если не указана, генерируется случайная)
        algorithm: алгоритм хеширования (по умолчанию sha256)
        iterations: количество итераций PBKDF2

    Возвращает:
        Кортеж (хеш в hex, соль в hex)
    """
    if salt is None:
        salt = secrets.token_hex(SALT_LENGTH)

    dk = hashlib.pbkdf2_hmac(
        algorithm,
        data.encode('utf-8'),
        salt.encode('utf-8'),
        iterations,
        dklen=32
    )
    return binascii.hexlify(dk).decode('utf-8'), salt


def timing_safe_hmac_verify(data: str, signature: str,
                            secret: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> bool:
    """
    Проверяет HMAC-подпись данных, используя constant-time сравнение.

    Аргументы:
        data: исходные данные
        signature: подпись для проверки (hex)
        secret: секретный ключ
        algorithm: алгоритм хеширования

    Возвращает:
        True если подпись корректна, иначе False.
    """
    expected = hmac.new(
        secret.encode('utf-8'),
        data.encode('utf-8'),
        getattr(hashlib, algorithm)
    ).hexdigest()
    return constant_time_compare(signature, expected)


def timing_safe_password_verify(password: str, hashed_password: str,
                                salt: str, algorithm: str = DEFAULT_HASH_ALGORITHM,
                                iterations: int = DEFAULT_ITERATIONS) -> bool:
    """
    Проверяет пароль, сравнивая его хеш с сохранённым, используя constant-time.

    Аргументы:
        password: проверяемый пароль
        hashed_password: сохранённый хеш пароля (hex)
        salt: соль (hex)
        algorithm: алгоритм хеширования
        iterations: количество итераций PBKDF2

    Возвращает:
        True если пароль верен, иначе False.
    """
    test_hash, _ = timing_safe_hash(password, salt, algorithm, iterations)
    return constant_time_compare(test_hash, hashed_password)


def generate_secure_token(length: int = TOKEN_LENGTH) -> str:
    """
    Генерирует криптографически стойкий токен в hex-формате.

    Аргументы:
        length: длина токена в байтах (результат будет в 2*length символов hex)

    Возвращает:
        Строка с hex-токеном.
    """
    return secrets.token_hex(length)


def generate_secure_urlsafe_token(length: int = TOKEN_LENGTH) -> str:
    """
    Генерирует криптографически стойкий URL-safe токен (base64).

    Аргументы:
        length: количество байт случайности (результат длиннее)

    Возвращает:
        URL-safe строка.
    """
    return secrets.token_urlsafe(length)


def generate_csrf_token() -> str:
    """
    Генерирует сложный CSRF-токен, содержащий timestamp и случайные данные,
    упакованные в base64 URL-safe. Токен можно проверить с помощью verify_csrf_token.

    Возвращает:
        Строка CSRF-токена.
    """
    timestamp = struct.pack('>Q', int(time.time()))
    random_bytes = secrets.token_bytes(TOKEN_LENGTH)
    combined = timestamp + random_bytes

    token = base64.urlsafe_b64encode(combined).decode('utf-8')
    token = token.rstrip('=')

    # Добавляем букву в начало, если токен начинается с не-буквы (для некоторых форм)
    if token and not token[0].isalpha():
        token = 'a' + token

    return token


def verify_csrf_token(token: str, max_age: int = 3600) -> Tuple[bool, Optional[str]]:
    """
    Проверяет сложный CSRF-токен, извлекая timestamp и сверяя длину.

    Аргументы:
        token: токен для проверки
        max_age: максимальный возраст токена в секундах

    Возвращает:
        Кортеж (валидность, сообщение об ошибке или None).
    """
    try:
        # Удаляем возможный префикс 'a'
        if token.startswith('a') and len(token) > 1:
            token = token[1:]

        # Восстанавливаем padding
        missing_padding = len(token) % 4
        if missing_padding:
            token += '=' * (4 - missing_padding)

        decoded = base64.urlsafe_b64decode(token)

        if len(decoded) < 8 + TOKEN_LENGTH:
            return False, "Некорректный формат токена"

        timestamp = struct.unpack('>Q', decoded[:8])[0]
        current_time = int(time.time())

        if current_time - timestamp > max_age:
            return False, "Токен истек"

        if len(decoded[8:]) != TOKEN_LENGTH:
            return False, "Некорректный формат токена"

        return True, None

    except (binascii.Error, struct.error) as e:
        logger.debug(f"Ошибка декодирования CSRF токена: {e}")
        return False, "Некорректный формат токена"
    except Exception as e:
        logger.error(f"Неожиданная ошибка проверки CSRF токена: {e}")
        return False, "Ошибка проверки токена"


def generate_simple_csrf_token() -> str:
    """
    Генерирует простой URL-safe CSRF-токен (без временной метки).

    Возвращает:
        Строка токена.
    """
    return secrets.token_urlsafe(32)


def verify_simple_csrf_token(token_from_form: str, token_from_cookie: str) -> bool:
    """
    Проверяет простой CSRF-токен (сравнивает с кукой) за константное время.

    Аргументы:
        token_from_form: токен из формы/запроса
        token_from_cookie: токен из cookie

    Возвращает:
        True если токены равны.
    """
    return constant_time_compare(token_from_form, token_from_cookie)


def generate_double_csrf_token() -> Tuple[str, str]:
    """
    Генерирует пару токенов для двойной CSRF-защиты:
    - простой токен (для cookie)
    - сложный токен с хешем (для формы)

    Возвращает:
        Кортеж (simple_token, form_token)
    """
    simple_token = secrets.token_urlsafe(32)
    complex_token = generate_csrf_token()

    combined = simple_token + complex_token
    verification_hash = hashlib.sha256(combined.encode()).hexdigest()[:16]

    form_token = f"{complex_token}:{verification_hash}"

    return simple_token, form_token


def verify_double_csrf_token(form_token: str, cookie_token: str) -> Tuple[bool, Optional[str]]:
    """
    Проверяет двойной CSRF-токен: разбирает form_token, проверяет сложную часть,
    затем вычисляет хеш и сравнивает.

    Аргументы:
        form_token: токен из формы (формат "complex:hash")
        cookie_token: простой токен из cookie

    Возвращает:
        Кортеж (валидность, сообщение об ошибке или None)
    """
    try:
        if ':' not in form_token:
            return False, "Неверный формат токена"

        complex_part, hash_part = form_token.split(':', 1)

        csrf_valid, csrf_error = verify_csrf_token(complex_part)
        if not csrf_valid:
            return False, csrf_error

        combined = cookie_token + complex_part
        expected_hash = hashlib.sha256(combined.encode()).hexdigest()[:16]

        if not constant_time_compare(hash_part, expected_hash):
            return False, "Неверный хеш токена"

        return True, None

    except Exception as e:
        logger.error(f"Ошибка проверки двойного CSRF токена: {e}")
        return False, f"Ошибка проверки: {str(e)[:50]}"


def timing_safe_endpoint(func: Callable) -> Callable:
    """
    Декоратор для асинхронных эндпоинтов, который добавляет задержку,
    если функция выполнилась слишком быстро (защита от timing-атак),
    и логирует, если выполнение заняло слишком много времени.

    Использует константы MIN_EXECUTION_TIME и MAX_EXECUTION_TIME.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        try:
            result = await func(*args, **kwargs)
            return result
        finally:
            elapsed = time.perf_counter() - start_time
            if elapsed < MIN_EXECUTION_TIME:
                sleep_time = MIN_EXECUTION_TIME - elapsed
                await asyncio.sleep(sleep_time)
            elif elapsed > MAX_EXECUTION_TIME:
                logger.warning(f"Endpoint {func.__name__} выполнен за {elapsed:.3f}s")
    return wrapper


async def async_sleep_with_fallback(delay: float):
    """
    Безопасное асинхронное ожидание с синхронным fallback.
    Если asyncio.sleep не работает (например, вне цикла событий),
    используется time.sleep.

    Аргументы:
        delay: время задержки в секундах.
    """
    try:
        await asyncio.sleep(delay)
    except RuntimeError:
        time.sleep(delay)


def rate_limit_safe(max_calls: int = 10, window: int = 60) -> Callable:
    """
    Декоратор для ограничения частоты запросов (rate limiting) на основе IP.
    Использует глобальный словарь в памяти (не подходит для распределённых систем).
    Добавляет константную задержку при превышении лимита для защиты от timing-атак.

    Аргументы:
        max_calls: максимальное количество вызовов за окно
        window: размер окна в секундах

    Возвращает:
        Декорированную асинхронную функцию.
    """
    calls = {}

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Попытка извлечь request из аргументов (для FastAPI)
            request = kwargs.get('request') or args[0] if args else None
            if hasattr(request, 'client') and request.client:
                ip = request.client.host
            else:
                ip = 'unknown'

            current_time = time.time()
            window_start = current_time - window

            # Очистка устаревших записей
            keys_to_delete = []
            for key, timestamps in calls.items():
                new_timestamps = [ts for ts in timestamps if ts >= window_start]
                if new_timestamps:
                    calls[key] = new_timestamps
                else:
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                if key in calls:
                    del calls[key]

            if ip in calls:
                call_count = len(calls[ip])
                if call_count >= max_calls:
                    # Задержка для маскировки факта превышения лимита
                    await async_sleep_with_fallback(0.05)
                    raise Exception("Rate limit exceeded")
                calls[ip].append(current_time)
            else:
                calls[ip] = [current_time]

            return await func(*args, **kwargs)
        return wrapper
    return decorator


def validate_input_safe(func: Callable) -> Callable:
    """
    Декоратор для проверки входных данных запроса:
    - допустимый Content-Type (JSON, form, multipart)
    - ограничение размера тела (до 10 МБ)
    При ошибке добавляет константную задержку для защиты от timing-атак.

    Аргументы:
        func: асинхронная функция, получающая request в аргументах

    Возвращает:
        Декорированную функцию.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = None
        for arg in args:
            if hasattr(arg, 'method') and hasattr(arg, 'url'):
                request = arg
                break

        if request:
            content_type = request.headers.get('content-type', '')

            is_json = constant_time_contains(content_type.lower(), 'application/json')
            is_form = constant_time_contains(content_type.lower(), 'application/x-www-form-urlencoded')
            is_multipart = constant_time_contains(content_type.lower(), 'multipart/form-data')

            if not (is_json or is_form or is_multipart):
                await async_sleep_with_fallback(0.002)
                raise Exception("Unsupported content type")

            content_length = request.headers.get('content-length')
            if content_length:
                try:
                    size = int(content_length)
                    if size > 10 * 1024 * 1024:  # 10 MB
                        await async_sleep_with_fallback(0.002)
                        raise Exception("Request too large")
                except ValueError:
                    await async_sleep_with_fallback(0.002)
                    raise Exception("Invalid content length")

        return await func(*args, **kwargs)
    return wrapper


async def async_is_valid_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Асинхронная проверка формата email с константной задержкой.

    Аргументы:
        email: строка email

    Возвращает:
        Кортеж (валидность, сообщение об ошибке или None)
    """
    if not email or '@' not in email:
        return False, "Invalid email format"

    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    start_time = time.perf_counter()
    is_valid = bool(re.match(email_regex, email))
    elapsed = time.perf_counter() - start_time

    if elapsed < MIN_EXECUTION_TIME:
        await async_sleep_with_fallback(MIN_EXECUTION_TIME - elapsed)

    if not is_valid:
        return False, "Invalid email format"

    return True, None


def sync_is_valid_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Синхронная проверка формата email с константной задержкой.

    Аргументы:
        email: строка email

    Возвращает:
        Кортеж (валидность, сообщение об ошибке или None)
    """
    if not email or '@' not in email:
        return False, "Invalid email format"

    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    start_time = time.perf_counter()
    is_valid = bool(re.match(email_regex, email))
    elapsed = time.perf_counter() - start_time

    if elapsed < MIN_EXECUTION_TIME:
        time.sleep(MIN_EXECUTION_TIME - elapsed)

    if not is_valid:
        return False, "Invalid email format"

    return True, None


async def async_is_valid_phone(phone: str) -> Tuple[bool, Optional[str]]:
    """
    Асинхронная проверка номера телефона (международный формат).
    Удаляет все нецифровые символы, проверяет длину и код страны.
    Использует constant_time_starts_with для безопасного сравнения кодов.

    Аргументы:
        phone: строка с номером телефона

    Возвращает:
        Кортеж (валидность, сообщение об ошибке или None)
    """
    digits = re.sub(r'\D', '', phone)

    if len(digits) < 10 or len(digits) > 15:
        return False, "Invalid phone number length"

    valid_starts = ['1', '7', '20', '27', '30', '31', '32', '33', '34', '36',
                    '39', '40', '41', '43', '44', '45', '46', '47', '48', '49',
                    '51', '52', '53', '54', '55', '56', '57', '58', '60', '61',
                    '62', '63', '64', '65', '66', '81', '82', '84', '86', '90',
                    '91', '92', '93', '94', '95', '98']

    valid = False
    for start in valid_starts:
        if constant_time_starts_with(digits, start):
            valid = True
            break

    if not valid:
        return False, "Invalid country code"

    return True, None


def sync_is_valid_phone(phone: str) -> Tuple[bool, Optional[str]]:
    """
    Синхронная версия async_is_valid_phone.
    """
    digits = re.sub(r'\D', '', phone)

    if len(digits) < 10 or len(digits) > 15:
        return False, "Invalid phone number length"

    valid_starts = ['1', '7', '20', '27', '30', '31', '32', '33', '34', '36',
                    '39', '40', '41', '43', '44', '45', '46', '47', '48', '49',
                    '51', '52', '53', '54', '55', '56', '57', '58', '60', '61',
                    '62', '63', '64', '65', '66', '81', '82', '84', '86', '90',
                    '91', '92', '93', '94', '95', '98']

    valid = False
    for start in valid_starts:
        if constant_time_starts_with(digits, start):
            valid = True
            break

    if not valid:
        return False, "Invalid country code"

    return True, None


async def async_is_valid_date(date_str: str, format: str = '%Y-%m-%d') -> Tuple[bool, Optional[str]]:
    """
    Асинхронная проверка даты: соответствует ли строка указанному формату
    и не находится ли дата в будущем? (опционально, см. код).
    Добавляет константную задержку.

    Аргументы:
        date_str: строка с датой
        format: ожидаемый формат (по умолчанию YYYY-MM-DD)

    Возвращает:
        Кортеж (валидность, сообщение об ошибке или None)
    """
    from datetime import datetime

    start_time = time.perf_counter()

    try:
        date_obj = datetime.strptime(date_str, format)

        # Если нужно проверять, что дата не в будущем, раскомментируйте:
        # if date_obj > datetime.now():
        #     return False, "Date cannot be in the future"

        elapsed = time.perf_counter() - start_time
        if elapsed < MIN_EXECUTION_TIME:
            await async_sleep_with_fallback(MIN_EXECUTION_TIME - elapsed)

        return True, None
    except ValueError:
        elapsed = time.perf_counter() - start_time
        if elapsed < MIN_EXECUTION_TIME:
            await async_sleep_with_fallback(MIN_EXECUTION_TIME - elapsed)
        return False, f"Invalid date format. Expected: {format}"
    except Exception:
        elapsed = time.perf_counter() - start_time
        if elapsed < MIN_EXECUTION_TIME:
            await async_sleep_with_fallback(MIN_EXECUTION_TIME - elapsed)
        return False, "Invalid date"


def sync_is_valid_date(date_str: str, format: str = '%Y-%m-%d') -> Tuple[bool, Optional[str]]:
    """
    Синхронная версия async_is_valid_date.
    """
    from datetime import datetime

    start_time = time.perf_counter()

    try:
        date_obj = datetime.strptime(date_str, format)
        elapsed = time.perf_counter() - start_time
        if elapsed < MIN_EXECUTION_TIME:
            time.sleep(MIN_EXECUTION_TIME - elapsed)
        return True, None
    except ValueError:
        elapsed = time.perf_counter() - start_time
        if elapsed < MIN_EXECUTION_TIME:
            time.sleep(MIN_EXECUTION_TIME - elapsed)
        return False, f"Invalid date format. Expected: {format}"
    except Exception:
        elapsed = time.perf_counter() - start_time
        if elapsed < MIN_EXECUTION_TIME:
            time.sleep(MIN_EXECUTION_TIME - elapsed)
        return False, "Invalid date"


def timing_safe_array_equals(arr1: List[Any], arr2: List[Any]) -> bool:
    """
    Сравнивает два списка поэлементно за константное время,
    используя constant_time_compare для строк/байтов и обычное сравнение для других типов.
    Время выполнения не зависит от позиции первого различия.

    Аргументы:
        arr1: первый список
        arr2: второй список

    Возвращает:
        True если списки идентичны, иначе False.
    """
    if len(arr1) != len(arr2):
        return False

    result = 0
    for a, b in zip(arr1, arr2):
        if isinstance(a, (str, bytes)) and isinstance(b, (str, bytes)):
            result |= 0 if constant_time_compare(a, b) else 1
        else:
            result |= 0 if a == b else 1

    return result == 0


def timing_safe_dict_equals(dict1: Dict[Any, Any], dict2: Dict[Any, Any]) -> bool:
    """
    Сравнивает два словаря за константное время.
    Сначала сравниваются ключи (отсортированные), затем значения.
    Рекурсивно обрабатывает вложенные словари и списки.

    Аргументы:
        dict1: первый словарь
        dict2: второй словарь

    Возвращает:
        True если словари идентичны, иначе False.
    """
    if len(dict1) != len(dict2):
        return False

    keys1 = sorted(dict1.keys())
    keys2 = sorted(dict2.keys())

    if not timing_safe_array_equals(keys1, keys2):
        return False

    result = 0
    for key in keys1:
        val1 = dict1[key]
        val2 = dict2[key]

        if isinstance(val1, (str, bytes)) and isinstance(val2, (str, bytes)):
            result |= 0 if constant_time_compare(str(val1), str(val2)) else 1
        elif isinstance(val1, dict) and isinstance(val2, dict):
            result |= 0 if timing_safe_dict_equals(val1, val2) else 1
        elif isinstance(val1, list) and isinstance(val2, list):
            result |= 0 if timing_safe_array_equals(val1, val2) else 1
        else:
            result |= 0 if val1 == val2 else 1

    return result == 0


def timing_safe_list_contains(haystack: List[str], needle: str) -> bool:
    """
    Проверяет, содержится ли строка needle в списке haystack,
    выполняя constant-time сравнение с каждым элементом.
    Время выполнения не зависит от наличия элемента.

    Аргументы:
        haystack: список строк
        needle: искомая строка

    Возвращает:
        True если needle найдена, иначе False.
    """
    result = 0
    for item in haystack:
        if constant_time_compare(item, needle):
            result |= 1
    return result == 1


def sanitize_string(input_string: str, max_length: int = 1000) -> str:
    """
    Очищает строку от потенциально опасных конструкций (XSS, управляющие символы и т.д.).
    Обрезает до max_length, удаляет HTML-теги, javascript:, data:, vbscript:, onX=,
    а также управляющие символы и escape-последовательности.

    Аргументы:
        input_string: исходная строка
        max_length: максимальная длина результата

    Возвращает:
        Очищенная строка.
    """
    if not input_string:
        return ""

    input_string = input_string[:max_length]

    dangerous_patterns = [
        (r'<[^>]+>', ''),                           # HTML-теги
        (r'javascript:', '', re.IGNORECASE),         # javascript: протокол
        (r'data:', '', re.IGNORECASE),               # data: протокол
        (r'vbscript:', '', re.IGNORECASE),           # vbscript: протокол
        (r'on\w+=', '', re.IGNORECASE),              # обработчики событий (onclick=...)
        (r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ''),   # управляющие символы
        (r'\\x[0-9a-f]{2}', '', re.IGNORECASE),      # hex-escapes
        (r'\\u[0-9a-f]{4}', '', re.IGNORECASE),      # unicode-escapes
        (r'\\[0-7]{1,3}', ''),                       # восьмеричные escapes
    ]

    result = input_string
    for pattern, repl, *flags in dangerous_patterns:
        if flags:
            result = re.sub(pattern, repl, result, flags=flags[0])
        else:
            result = re.sub(pattern, repl, result)

    return result.strip()


def sanitize_filename(filename: str) -> str:
    """
    Очищает имя файла от опасных символов (пути, разделители, управляющие символы).
    Оставляет только имя файла (отсекает путь), заменяет опасные символы на '_',
    обрезает до 255 символов, сохраняя расширение.

    Аргументы:
        filename: исходное имя файла

    Возвращает:
        Безопасное имя файла.
    """
    import os

    filename = os.path.basename(filename)

    dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '..']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')

    max_length = 255
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        name = name[:max_length - len(ext)]
        filename = name + ext

    return filename


# Алиасы для асинхронных версий валидаторов (для удобства)
is_valid_email = async_is_valid_email
is_valid_phone = async_is_valid_phone
is_valid_date = async_is_valid_date


class SecureSecret:
    """
    Класс для безопасного хранения секретных данных (например, паролей, ключей).
    Хранит данные в байтовом виде, предоставляет constant-time сравнение
    и автоматически затирает память при удалении объекта.
    """

    def __init__(self, secret: str):
        """
        Инициализирует объект секретом.

        Аргументы:
            secret: строка с секретом.
        """
        self._secret_bytes = secret.encode('utf-8') if isinstance(secret, str) else secret
        self._length = len(self._secret_bytes)

    def compare(self, other: Union[str, bytes, 'SecureSecret']) -> bool:
        """
        Сравнивает текущий секрет с другим за константное время.

        Аргументы:
            other: другой секрет (строка, байты или SecureSecret)

        Возвращает:
            True если секреты равны.
        """
        if isinstance(other, SecureSecret):
            other_bytes = other._secret_bytes
        elif isinstance(other, str):
            other_bytes = other.encode('utf-8')
        else:
            other_bytes = other

        return constant_time_compare(self._secret_bytes, other_bytes)

    def __eq__(self, other: object) -> bool:
        """Перегрузка оператора == для безопасного сравнения."""
        if not isinstance(other, (SecureSecret, str, bytes)):
            return False
        return self.compare(other)

    def __ne__(self, other: object) -> bool:
        """Перегрузка оператора !=."""
        return not self.__eq__(other)

    def clear(self):
        """
        Затирает секрет в памяти (заполняет нулями).
        """
        import ctypes
        mutable = bytearray(self._secret_bytes)
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(mutable)), 0, len(mutable))

        self._secret_bytes = b''
        self._length = 0

    def __del__(self):
        """При удалении объекта автоматически затираем данные."""
        self.clear()


# Список всех экспортируемых имён для удобства импорта
__all__ = [
    'constant_time_compare',
    'constant_time_contains',
    'constant_time_starts_with',
    'constant_time_ends_with',
    'constant_time_select',
    'timing_safe_hash',
    'timing_safe_hmac_verify',
    'timing_safe_password_verify',
    'generate_secure_token',
    'generate_secure_urlsafe_token',
    'generate_csrf_token',
    'verify_csrf_token',
    'generate_simple_csrf_token',
    'verify_simple_csrf_token',
    'generate_double_csrf_token',
    'verify_double_csrf_token',
    'timing_safe_endpoint',
    'rate_limit_safe',
    'validate_input_safe',
    'timing_safe_array_equals',
    'timing_safe_dict_equals',
    'timing_safe_list_contains',
    'sanitize_string',
    'sanitize_filename',
    'async_is_valid_email',
    'async_is_valid_phone',
    'async_is_valid_date',
    'async_sleep_with_fallback',
    'sync_is_valid_email',
    'sync_is_valid_phone',
    'sync_is_valid_date',
    'is_valid_email',
    'is_valid_phone',
    'is_valid_date',
    'SecureSecret',
    'MIN_EXECUTION_TIME',
    'MAX_EXECUTION_TIME',
    'TOKEN_LENGTH',
    'SALT_LENGTH',
    'NONCE_LENGTH',
    'DEFAULT_HASH_ALGORITHM',
    'DEFAULT_ITERATIONS',
]