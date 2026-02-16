# Технический скрипт для создания пользователя для тестов
from app.database import SessionLocal
from app.models import User
from datetime import datetime

db = SessionLocal()

# Проверяем, есть ли уже пользователь
user = db.query(User).filter(User.username == "test").first()
if not user:
    user = User(
        username="test",
        email="test@test.com",
        phone="79991234567",
        confirmed=True,
        is_admin=False,
        created_at=datetime.utcnow(),
        locked_until=None,
        failed_login_attempts=0
    )
    user.set_password("test1234")
    db.add(user)
    db.commit()
    print("✅ Тестовый пользователь создан: test / test1234")
else:
    print("ℹ️ Тестовый пользователь уже существует")

db.close()