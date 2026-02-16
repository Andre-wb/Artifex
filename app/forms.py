"""
Модуль для определения форм регистрации и входа.
Использует dataclasses для создания простых полей HTML-форм.
Позволяет генерировать HTML-код полей ввода с заданными атрибутами.
"""

from typing import Optional, Any
from dataclasses import dataclass


@dataclass
class FormField:
    """
    Представляет одно поле формы.
    Содержит идентификатор, метку и имя поля.
    При вызове экземпляра возвращает HTML-строку <input> с переданными атрибутами.
    """

    id: str
    label: Any
    name: str

    def __call__(self, **kwargs):
        """
        Генерирует HTML-код поля ввода.
        :param kwargs: дополнительные атрибуты (например, class, placeholder)
        :return: строка вида <input type="text" id="..." name="..." ...>
        """
        attrs = ' '.join([f'{k}="{v}"' for k, v in kwargs.items()])
        return f'<input type="text" id="{self.id}" name="{self.name}" {attrs}>'


@dataclass
class Form:
    """
    Составная форма, содержащая несколько полей.
    Предоставляет доступ к полям как к атрибутам и словарь fields.
    """

    username: FormField
    email: FormField
    phone: FormField
    password: FormField
    confirm: FormField
    credential: FormField

    def __post_init__(self):
        """Инициализирует словарь fields для удобного доступа по имени."""
        self.fields = {
            'username': self.username,
            'email': self.email,
            'phone': self.phone,
            'password': self.password,
            'confirm': self.confirm,
            'credential': self.credential
        }

    def hidden_tag(self):
        """
        Заглушка для CSRF-токена или скрытых полей.
        В текущей реализации ничего не возвращает.
        """
        return ''

    def __getattr__(self, name):
        """
        Позволяет обращаться к полям формы через точку (form.username).
        Если атрибут не найден, ищет в словаре fields.
        """
        if name in self.fields:
            return self.fields[name]
        raise AttributeError(f"'Form' object has no attribute '{name}'")


# Форма регистрации: все поля заполняются отдельно
register_form = Form(
    username=FormField(id="username", label="Имя пользователя", name="username"),
    email=FormField(id="email", label="Email", name="email"),
    phone=FormField(id="phone", label="Телефон", name="phone"),
    password=FormField(id="password", label="Пароль", name="password"),
    confirm=FormField(id="confirm", label="Подтвердите пароль", name="confirm"),
    credential=FormField(id="credential", label="", name="credential")  # не используется в регистрации
)

# Форма входа: поля username, email, phone используют одно и то же имя "credential"
# для приёма логина (может быть email, телефон или имя пользователя).
# Поле confirm не используется, но оставлено для совместимости.
login_form = Form(
    username=FormField(id="username", label="Имя пользователя", name="credential"),
    email=FormField(id="email", label="", name="credential"),
    phone=FormField(id="phone", label="", name="credential"),
    password=FormField(id="password", label="Пароль", name="password"),
    confirm=FormField(id="confirm", label="", name="confirm"),
    credential=FormField(id="credential", label="Email или телефон", name="credential")
)