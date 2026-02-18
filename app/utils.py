import secrets
import random
import string

def generate_invite_code(length: int = 8) -> str:
    """
    Генерирует случайный код приглашения.
    """
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=length))