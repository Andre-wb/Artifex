"""
Модуль безопасности для работы с паролями.
Содержит функции для валидации сложности пароля, генерации безопасных паролей,
оценки их стойкости, а также хеширования и проверки паролей с использованием PBKDF2.
"""

import re
import secrets
import hashlib
from typing import Tuple


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Проверяет, соответствует ли пароль требованиям безопасности.

    Требования:
    - Длина от 8 до 128 символов.
    - Содержит хотя бы одну заглавную букву (латиница или кириллица).
    - Содержит хотя бы одну строчную букву.
    - Содержит хотя бы одну цифру.
    - Содержит хотя бы один специальный символ из списка !@#$%^&*(),.?":{}|<>[]\/+=_-.
    - Не является слишком простым (не входит в список распространённых паролей).
    - Не содержит повторяющихся символов более 3 раз.
    - Не содержит простых последовательностей (012, qwerty, abc и т.п.).
    - Не похож на дату.
    - Не соответствует простому шаблону типа "СловоЦифрыСимвол".

    Аргументы:
        password: строка пароля для проверки.

    Возвращает:
        Кортеж (успех, сообщение об ошибке). Если успех = True, сообщение пустое.
    """
    if len(password) < 8:
        return False, "Пароль должен быть не менее 8 символов"

    if len(password) > 128:
        return False, "Пароль не должен превышать 128 символов"

    # Основные проверки на наличие разных классов символов
    checks = [
        (r'[A-ZА-Я]', "Пароль должен содержать хотя бы одну заглавную букву"),
        (r'[a-zа-я]', "Пароль должен содержать хотя бы одну строчную букву"),
        (r'\d', "Пароль должен содержать хотя бы одну цифру"),
        (r'[!@#$%^&*(),.?":{}|<>\[\]\\/+=_\-]', "Пароль должен содержать хотя бы один специальный символ"),
    ]

    for pattern, error in checks:
        if not re.search(pattern, password):
            return False, error

    # Список наиболее распространённых паролей (исключаем)
    common_passwords = [
        "password", "123456", "qwerty", "admin", "welcome",
        "password123", "12345678", "123456789", "123123", "111111",
        "пароль", "1234567890", "йцукен", "андрей", "максим",
        "letmein", "monkey", "dragon", "baseball", "football",
        "master", "hello", "freedom", "whatever", "qazwsx",
        "trustno1", "sunshine", "iloveyou", "starwars", "princess"
    ]

    if password.lower() in common_passwords:
        return False, "Пароль слишком простой, используйте более сложную комбинацию"

    # Запрет на большое количество повторяющихся символов (например, aaaa)
    if re.search(r'(.)\1{3,}', password):
        return False, "Пароль содержит слишком много повторяющихся символов"

    # Запрет на простые последовательности
    sequences = [
        r'(012|123|234|345|456|567|678|789|890|098|987|876|765|654|543|432|321|210)',
        r'(qwerty|asdfgh|zxcvbn|йцукен|фывапр|ячсмит)',
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
        r'(abcdef|bcdefg|cdefgh|defghi|efghij|fghijk|ghijkl|hijklm|ijklmn|jklmno|klmnop|lmnopq|mnopqr|nopqrs|opqrst|pqrstu|qrstuv|rstuvw|stuvwx|tuvwxy|uvwxyz)',
    ]

    for pattern in sequences:
        if re.search(pattern, password.lower()):
            return False, "Пароль содержит простую последовательность символов"

    # Запрет на даты (например, 19900101 или 01011990)
    date_patterns = [
        r'\d{4}[01]\d[0-3]\d',
        r'[0-3]\d[01]\d\d{4}',
    ]

    for pattern in date_patterns:
        if re.fullmatch(pattern, password):
            return False, "Пароль похож на дату. Используйте более сложную комбинацию"

    # Запрет на слишком простой шаблон (СловоЦифрыСимвол)
    if re.match(r'^[A-Z][a-z]+\d+[!@#$%^&*()]?$', password):
        return False, "Пароль соответствует слишком простому шаблону (СловоЦифрыСимвол)"

    return True, ""


def check_password_against_user_data(password: str, username: str = "", email: str = "") -> Tuple[bool, str]:
    """
    Дополнительная проверка, чтобы пароль не содержал имя пользователя или части email.

    Аргументы:
        password: проверяемый пароль.
        username: имя пользователя.
        email: email пользователя.

    Возвращает:
        Кортеж (успех, сообщение об ошибке).
    """
    password_lower = password.lower()

    if username and username.lower() in password_lower:
        return False, "Пароль не должен содержать ваше имя пользователя"

    if email:
        # Проверяем локальную часть email (до @)
        email_local = email.lower().split('@')[0]
        if email_local and len(email_local) > 2 and email_local in password_lower:
            return False, "Пароль не должен содержать часть вашего email"

        # Проверяем домен (без зоны, например, gmail из gmail.com)
        if '@' in email:
            email_domain = email.lower().split('@')[1].split('.')[0]
            if email_domain and len(email_domain) > 2 and email_domain in password_lower:
                return False, "Пароль не должен содержать часть вашего домена email"

    return True, ""


def generate_secure_password(length: int = 16) -> str:
    """
    Генерирует криптографически стойкий пароль, удовлетворяющий требованиям.

    Аргументы:
        length: желаемая длина пароля (минимум 12, максимум 64).

    Возвращает:
        Строка пароля.
    """
    if length < 12:
        length = 12
    if length > 64:
        length = 64

    import string

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Гарантируем наличие хотя бы одного символа каждого класса
    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]

    all_chars = lowercase + uppercase + digits + symbols

    remaining_length = length - 4
    if remaining_length > 0:
        password_chars.extend(secrets.choice(all_chars) for _ in range(remaining_length))

    # Перемешиваем, чтобы первые символы не были предсказуемыми
    secrets.SystemRandom().shuffle(password_chars)

    password = ''.join(password_chars)

    # Рекурсивно перегенерируем, если пароль не прошёл валидацию (редкий случай)
    is_valid, _ = validate_password(password)
    if not is_valid:
        return generate_secure_password(length)

    return password


def calculate_password_strength(password: str) -> dict:
    """
    Оценивает стойкость пароля, возвращает словарь с баллами, уровнем,
    цветом для отображения и списком замечаний.

    Аргументы:
        password: строка пароля.

    Возвращает:
        Словарь:
            - score: целое число от 0 до 100.
            - strength: текстовое описание ("Очень слабый", "Слабый", ...).
            - color: цвет для индикатора (green, lightgreen, orange, red, darkred).
            - feedback: список строк с замечаниями.
            - length: длина пароля.
            - has_upper: есть ли заглавные буквы.
            - has_lower: есть ли строчные буквы.
            - has_digits: есть ли цифры.
            - has_symbols: есть ли специальные символы.
    """
    score = 0
    max_score = 100
    feedback = []

    length = len(password)
    if length >= 12:
        score += 25
        feedback.append("✓ Длина пароля отличная")
    elif length >= 8:
        score += 15
        feedback.append("✓ Длина пароля хорошая")
    else:
        feedback.append("✗ Пароль слишком короткий")

    checks = [
        (r'[A-ZА-Я]', 10, "Заглавные буквы"),
        (r'[a-zа-я]', 10, "Строчные буквы"),
        (r'\d', 10, "Цифры"),
        (r'[!@#$%^&*(),.?":{}|<>\[\]\\/+=_\-]', 15, "Специальные символы"),
    ]

    for pattern, points, description in checks:
        if re.search(pattern, password):
            score += points
            feedback.append(f"✓ Содержит {description.lower()}")
        else:
            feedback.append(f"✗ Не содержит {description.lower()}")

    # Штрафы за слабые места
    penalties = [
        (r'(.)\1{3,}', 20, "Много повторяющихся символов"),
        (r'(012|123|234|345|456|567|678|789|890)', 15, "Числовая последовательность"),
        (r'(qwerty|asdfgh|zxcvbn)', 20, "Клавиатурная последовательность"),
    ]

    for pattern, penalty, reason in penalties:
        if re.search(pattern, password.lower()):
            score -= penalty
            feedback.append(f"⚠ {reason}")

    # Сильный штраф за слишком распространённый пароль
    common_passwords = ["password", "123456", "qwerty", "admin"]
    if password.lower() in common_passwords:
        score = 0
        feedback.append("✗ Очень распространенный пароль")

    score = max(0, min(score, max_score))

    if score >= 80:
        strength = "Очень сильный"
        color = "green"
    elif score >= 60:
        strength = "Сильный"
        color = "lightgreen"
    elif score >= 40:
        strength = "Средний"
        color = "orange"
    elif score >= 20:
        strength = "Слабый"
        color = "red"
    else:
        strength = "Очень слабый"
        color = "darkred"

    return {
        "score": score,
        "strength": strength,
        "color": color,
        "feedback": feedback,
        "length": length,
        "has_upper": bool(re.search(r'[A-ZА-Я]', password)),
        "has_lower": bool(re.search(r'[a-zа-я]', password)),
        "has_digits": bool(re.search(r'\d', password)),
        "has_symbols": bool(re.search(r'[!@#$%^&*(),.?":{}|<>\[\]\\/+=_\-]', password)),
    }


def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
    """
    Хеширует пароль с солью, используя PBKDF2-HMAC-SHA256.
    Количество итераций: 100000, выходная длина: 32 байта (256 бит).

    Аргументы:
        password: строка пароля.
        salt: соль в hex (если не указана, генерируется случайная).

    Возвращает:
        Кортеж (хеш в hex, соль в hex).
    """
    if salt is None:
        salt = secrets.token_hex(16)  # 16 байт -> 32 символа hex

    iterations = 100000

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        iterations,
        dklen=32
    )
    return key.hex(), salt


def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """
    Проверяет пароль, сравнивая его хеш с сохранённым.
    Используется constant-time сравнение для защиты от timing-атак.

    Аргументы:
        password: проверяемый пароль.
        hashed_password: сохранённый хеш (hex).
        salt: соль (hex).

    Возвращает:
        True если пароль верен, иначе False.
    """
    test_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(test_hash, hashed_password)