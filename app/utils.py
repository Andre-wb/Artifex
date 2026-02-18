import secrets
import string

def generative_invite_code(length=8):
    """Генерирует уникальный код приглашения
    из букв и цифр, исключая похожие символы."""

    alphabet = string.ascii_uppercase + string.digits

    for ch in 'O0I1':
        alphabet = alphabet.replace(ch, '')
    return ''.join(secrets.choice(alphabet) for _ in range(length))