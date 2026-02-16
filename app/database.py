"""
Модуль для работы с базой данных SQLite через SQLAlchemy.

Предоставляет:
- Подключение к SQLite с настройками, подходящими для многопоточного приложения.
- Сессию SQLAlchemy (SessionLocal).
- Базовый класс для моделей (Base).
- Функции для получения сессии (get_db, get_db_context).
- Безопасное выполнение SQL-запросов с валидацией (защита от опасных операций).
- Логирование выполняемых запросов (с маскированием длинных параметров).
- Санитизацию идентификаторов таблиц и колонок.
- Динамическое построение простых запросов с проверкой безопасности.
"""

from sqlalchemy import create_engine, event, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from contextlib import contextmanager
from .config import Config  # предполагается, что Config содержит метод get_database_url()
import logging
from typing import Optional, Dict, Any, Union, Tuple, List
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

# Константы для безопасного SQL
ALLOWED_QUERY_PREFIXES = {'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WITH'}
DANGEROUS_KEYWORDS = {
    'DROP', 'TRUNCATE', 'ALTER', 'CREATE', 'EXEC', 'EXECUTE',
    'XP_', 'SP_', 'SHUTDOWN', 'GRANT', 'REVOKE'
}
MAX_QUERY_LENGTH = 10000  # Максимальная длина SQL-запроса


@event.listens_for(Engine, "before_cursor_execute")
def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """
    Событие SQLAlchemy, вызываемое перед выполнением курсора.
    Используется для логирования SQL-запросов (в режиме DEBUG) с маскированием длинных параметров.
    """
    if logger.isEnabledFor(logging.DEBUG):
        # Обрезаем длинные запросы для лога
        log_statement = statement[:500] + "..." if len(statement) > 500 else statement

        # Маскируем параметры, если они слишком длинные (например, пароли, токены)
        if parameters:
            if isinstance(parameters, dict):
                masked_params = {
                    k: '***' if isinstance(v, (str, bytes)) and len(str(v)) > 20 else v
                    for k, v in parameters.items()
                }
            elif isinstance(parameters, (tuple, list)):
                masked_params = tuple(
                    '***' if isinstance(v, (str, bytes)) and len(str(v)) > 20 else v
                    for v in parameters
                )
            else:
                masked_params = '***'
        else:
            masked_params = parameters

        logger.debug(f"SQL: {log_statement}, Params: {masked_params}")


# Создание движка SQLAlchemy для SQLite
# URL базы данных берётся из конфигурации (например, "sqlite:///./app.db")
database_url = Config.get_database_url()

# Для SQLite важно указать check_same_thread=False, если приложение многопоточное,
# иначе SQLite будет блокировать доступ из разных потоков.
# Параметры пула для SQLite не имеют смысла, но их можно оставить без ошибок.
engine = create_engine(
    database_url,
    connect_args={"check_same_thread": False},  # разрешаем использование в разных потоках
    pool_pre_ping=True,     # для других БД полезно, для SQLite игнорируется
    pool_recycle=3600,      # для SQLite не имеет значения
    pool_size=10,           # для SQLite игнорируется (SQLite использует один поток)
    max_overflow=20,        # игнорируется
    echo=False,             # отключаем echo SQLAlchemy (используем своё логирование)
)

# Фабрика сессий
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=Session
)

# Базовый класс для моделей
Base = declarative_base()


def get_db():
    """
    Генератор для получения сессии базы данных (используется в FastAPI через Depends).
    Автоматически закрывает сессию после завершения запроса.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Ошибка в сессии БД: {e}")
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Контекстный менеджер для работы с сессией БД вне FastAPI (например, в фоновых задачах).
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Ошибка в контексте БД: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def _validate_sql_query(query: str) -> None:
    """
    Проверяет SQL-запрос на соответствие политикам безопасности:
    - максимальная длина,
    - разрешённый первый оператор (SELECT, INSERT, UPDATE, DELETE, WITH),
    - отсутствие опасных ключевых слов (DROP, TRUNCATE и т.д.) вне строк и комментариев.
    В случае нарушения выбрасывает ValueError.
    """
    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f"Слишком длинный SQL запрос (максимум {MAX_QUERY_LENGTH} символов)")

    query_upper = query.upper()

    # Извлекаем первый значимый токен (игнорируя комментарии и пустые строки)
    lines = query_upper.split('\n')
    first_keyword = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith('--') or line.startswith('/*'):
            continue
        # Удаляем однострочный комментарий после --
        if '--' in line:
            line = line.split('--')[0]
        parts = line.split()
        if parts:
            first_keyword = parts[0]
            break

    if not first_keyword:
        raise ValueError("Пустой SQL запрос")

    if first_keyword not in ALLOWED_QUERY_PREFIXES:
        raise ValueError(f"Запрещенный тип запроса. Разрешены только: {', '.join(ALLOWED_QUERY_PREFIXES)}")

    # Поиск опасных ключевых слов вне строк и комментариев
    pos = 0
    while pos < len(query_upper):
        # Пропускаем однострочные комментарии
        if query_upper.startswith('--', pos):
            pos = query_upper.find('\n', pos)
            if pos == -1:
                break
            continue

        # Пропускаем многострочные комментарии
        if query_upper.startswith('/*', pos):
            end_comment = query_upper.find('*/', pos)
            if end_comment == -1:
                break
            pos = end_comment + 2
            continue

        # Пропускаем строки в одинарных кавычках
        if query_upper[pos] == "'":
            end_quote = query_upper.find("'", pos + 1)
            if end_quote == -1:
                break
            pos = end_quote + 1
            continue

        # Проверяем каждое опасное ключевое слово
        for keyword in DANGEROUS_KEYWORDS:
            keyword_pos = query_upper.find(keyword, pos)
            if keyword_pos == -1:
                continue

            # Убедимся, что это отдельное слово (не часть другого слова)
            before = keyword_pos == 0 or not query_upper[keyword_pos-1].isalnum()
            after_pos = keyword_pos + len(keyword)
            after = after_pos >= len(query_upper) or not query_upper[after_pos].isalnum()

            if before and after:
                raise ValueError(f"Обнаружено опасное ключевое слово в запросе: {keyword}")

            # Если слово не полностью отдельное, продолжаем поиск
        pos += 1


def execute_safe_query(db: Session, query: str, params: Optional[Dict[str, Any]] = None):
    """
    Выполняет SQL-запрос с валидацией безопасности.
    Для SELECT возвращает список строк, для остальных - результат после commit.
    В случае ошибки выполняет rollback.
    """
    try:
        _validate_sql_query(query)

        stmt = text(query)
        result = db.execute(stmt, params or {})

        if query.strip().upper().startswith('SELECT'):
            return result.fetchall()

        db.commit()
        return result

    except Exception as e:
        logger.error(f"Ошибка выполнения запроса: {e}")
        db.rollback()
        raise


def sanitize_sql_identifier(identifier: str) -> str:
    """
    Очищает идентификатор (имя таблицы, колонки) от потенциально опасных символов.
    Допускаются только буквы ASCII, цифры, подчёркивание и точка.
    Если идентификатор начинается с цифры, добавляет подчёркивание.
    Обрезает до 255 символов.
    """
    if not identifier:
        raise ValueError("Идентификатор не может быть пустым")

    # Оставляем только ASCII символы
    sanitized = ''.join(c for c in identifier if c.isascii())

    # Оставляем только буквы, цифры, подчёркивание и точку
    sanitized = ''.join(c for c in sanitized if c.isalnum() or c in ('_', '.'))

    # Если первый символ - цифра, добавляем подчёркивание
    if sanitized and sanitized[0].isdigit():
        sanitized = '_' + sanitized

    # Обрезаем до разумной длины
    if len(sanitized) > 255:
        sanitized = sanitized[:255]

    if not sanitized:
        raise ValueError(f"Некорректный идентификатор: {identifier}")

    return sanitized


def execute_dynamic_query(
        db: Session,
        table_name: str,
        operation: str = 'SELECT',
        columns: Optional[List[str]] = None,
        where_clause: Optional[str] = None,
        where_params: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None
):
    """
    Динамически строит и выполняет простой SQL-запрос.
    Поддерживает SELECT и DELETE (с необязательным WHERE).
    INSERT и UPDATE требуют дополнительной логики и здесь не реализованы.

    Аргументы:
        db: сессия SQLAlchemy.
        table_name: имя таблицы (будет очищено через sanitize_sql_identifier).
        operation: 'SELECT' или 'DELETE'.
        columns: список колонок для SELECT (если None, то '*').
        where_clause: условие WHERE (без ключевого слова WHERE), например "id = :user_id".
        where_params: параметры для where_clause.
        limit: максимальное количество записей (только для SELECT, не более 1000).

    Возвращает:
        Для SELECT: список строк.
        Для DELETE: результат выполнения.

    Исключения:
        ValueError при нарушении безопасности.
    """
    operation = operation.upper()
    if operation not in ALLOWED_QUERY_PREFIXES:
        raise ValueError(f"Недопустимая операция: {operation}")

    # Санитизация имени таблицы
    safe_table = sanitize_sql_identifier(table_name)

    # Санитизация списка колонок
    if columns:
        safe_columns = [sanitize_sql_identifier(col) for col in columns]
        columns_str = ', '.join(safe_columns)
    else:
        columns_str = '*'

    # Построение базового запроса
    if operation == 'SELECT':
        query = f"SELECT {columns_str} FROM {safe_table}"
    elif operation == 'DELETE':
        query = f"DELETE FROM {safe_table}"
    else:
        # Другие операции (INSERT, UPDATE) не реализованы в этой упрощённой версии
        raise NotImplementedError(f"Операция {operation} через execute_dynamic_query не реализована")

    # Добавление WHERE
    if where_clause:
        # Проверка, что where_clause не содержит опасных ключевых слов
        where_upper = where_clause.upper()
        for keyword in DANGEROUS_KEYWORDS:
            if keyword in where_upper:
                raise ValueError(f"Опасное ключевое слово в условии WHERE: {keyword}")

        # Запрещаем повторное указание WHERE
        if 'WHERE' in where_upper:
            raise ValueError("Не указывайте ключевое слово WHERE в where_clause")

        query += f" WHERE {where_clause}"

    # Добавление LIMIT (только для SELECT)
    if limit is not None and operation == 'SELECT':
        if not isinstance(limit, int) or limit <= 0:
            raise ValueError("LIMIT должен быть положительным целым числом")
        if limit > 1000:  # Защита от чрезмерно больших выборок
            raise ValueError("LIMIT не может превышать 1000")
        query += f" LIMIT {limit}"

    # Выполнение запроса
    return execute_safe_query(db, query, where_params or {})