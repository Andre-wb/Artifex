# технический скрипт для инициализации БД
from app.database import engine
from app.models import Base

# Создание таблиц
Base.metadata.create_all(bind=engine)

print("✅ Таблицы дневника созданы успешно!")