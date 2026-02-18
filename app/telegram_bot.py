"""
Telegram-бот для напоминаний о домашних заданиях (библиотека telebot).
"""
import logging
import threading
import time
from datetime import datetime, timedelta

import telebot
from telebot import types
from sqlalchemy.orm import Session

from app.config import Config
from app.database import SessionLocal
from app.models import User, Lesson
from app.auth import verify_2fa_token

logger = logging.getLogger(__name__)

bot = telebot.TeleBot(Config.TELEGRAM_BOT_TOKEN, parse_mode='HTML')


def get_user_by_telegram_id(telegram_id: int) -> User | None:
    """Возвращает пользователя по telegram_id."""
    db = SessionLocal()
    try:
        return db.query(User).filter(User.telegram_id == telegram_id).first()
    finally:
        db.close()


def update_user_telegram_id(user_id: int, telegram_id: int) -> bool:
    """Привязывает telegram_id к пользователю."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        user.telegram_id = telegram_id
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Ошибка привязки Telegram: {e}")
        db.rollback()
        return False
    finally:
        db.close()


@bot.message_handler(commands=['start'])
def handle_start(message: types.Message):
    """
    Обработчик команды /start.
    Если передан параметр (например, /start ABC123), проверяем токен и привязываем аккаунт.
    Иначе выводим приветствие и инструкцию.
    """
    chat_id = message.chat.id
    args = message.text.split()
    token = args[1] if len(args) > 1 else None

    if not token:
        bot.send_message(
            chat_id,
            "👋 Привет! Я бот для напоминаний о домашних заданиях.\n"
            "Чтобы привязать аккаунт, перейдите на сайт, войдите в профиль и нажмите 'Привязать Telegram'.\n"
            "Затем перейдите по полученной ссылке."
        )
        return

    # Проверяем токен (срок действия 10 минут, как в 2FA)
    user_id = verify_2fa_token(token)
    if not user_id:
        bot.send_message(
            chat_id,
            "❌ Неверный или просроченный код.\n"
            "Перейдите на сайт и сгенерируйте новый код в профиле."
        )
        return

    # Привязываем пользователя
    if update_user_telegram_id(user_id, message.from_user.id):
        bot.send_message(
            chat_id,
            "✅ Ваш Telegram аккаунт успешно привязан к дневнику!\n"
            "Теперь вы будете получать напоминания о домашних заданиях.\n"
            "Используйте /help для просмотра доступных команд."
        )
    else:
        bot.send_message(chat_id, "❌ Произошла ошибка при привязке. Попробуйте позже.")


@bot.message_handler(commands=['help'])
def handle_help(message: types.Message):
    bot.send_message(
        message.chat.id,
        "Доступные команды:\n"
        "/start - привязать аккаунт (с токеном из профиля)\n"
        "/set_reminder <часы> - установить время напоминания (по умолчанию 24)\n"
        "/help - эта справка"
    )


@bot.message_handler(commands=['set_reminder'])
def handle_set_reminder(message: types.Message):
    """
    Устанавливает количество часов до дедлайна, за которое нужно прислать напоминание.
    """
    chat_id = message.chat.id
    user = get_user_by_telegram_id(message.from_user.id)
    if not user:
        bot.send_message(chat_id, "❌ Ваш Telegram не привязан. Используйте /start с токеном.")
        return

    args = message.text.split()
    if len(args) != 2:
        bot.send_message(chat_id, "Использование: /set_reminder <число часов>")
        return

    try:
        hours = int(args[1])
        if hours < 1 or hours > 72:
            bot.send_message(chat_id, "Часы должны быть от 1 до 72.")
            return
    except ValueError:
        bot.send_message(chat_id, "Введите число.")
        return

    # Сохраняем в БД
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user.id).first()
        user.reminder_hours_before = hours
        db.commit()
        bot.send_message(chat_id, f"✅ Время напоминания установлено на {hours} часов.")
    except Exception as e:
        logger.error(f"Ошибка установки напоминания: {e}")
        bot.send_message(chat_id, "❌ Ошибка при сохранении.")
    finally:
        db.close()


def send_reminders():
    """
    Проверяет предстоящие уроки с домашним заданием и отправляет уведомления в Telegram.
    Запускается в отдельном потоке по расписанию.
    """
    logger.info("Запуск отправки напоминаний...")
    db = SessionLocal()
    now = datetime.utcnow()

    # Все пользователи с привязанным Telegram
    users = db.query(User).filter(User.telegram_id != None).all()

    for user in users:
        hours_before = user.reminder_hours_before or 24
        target_time = now + timedelta(hours=hours_before)
        start_window = target_time - timedelta(minutes=15)
        end_window = target_time + timedelta(minutes=15)

        # Уроки на сегодня и завтра (упрощённо, можно улучшить с учётом времени)
        today = now.date()
        tomorrow = today + timedelta(days=1)
        lessons = db.query(Lesson).filter(
            Lesson.user_id == user.id,
            Lesson.date.in_([today, tomorrow]),
            Lesson.homework != None,
            Lesson.homework != ''
        ).all()

        for lesson in lessons:
            # Если урок завтра, отправляем напоминание
            if lesson.date == tomorrow:
                text = (
                    f"📚 <b>Напоминание о домашнем задании</b>\n"
                    f"Завтра ({lesson.date.strftime('%d.%m')}) урок {lesson.lesson_number} – {lesson.subject.name}\n"
                    f"📝 <b>Задание:</b> {lesson.homework[:100]}{'...' if len(lesson.homework) > 100 else ''}"
                )
                try:
                    bot.send_message(user.telegram_id, text)
                except Exception as e:
                    logger.error(f"Ошибка отправки пользователю {user.id}: {e}")
    db.close()


def run_bot():
    """Запускает бота в отдельном потоке (бесконечный поллинг)."""
    logger.info("Telegram бот запущен")
    bot.infinity_polling(skip_pending=True)


# Поток для отправки напоминаний по расписанию
def reminder_worker(interval_minutes=15):
    """
    Фоновый поток, который каждые interval_minutes вызывает send_reminders.
    """
    while True:
        send_reminders()
        time.sleep(interval_minutes * 60)

def start_bot():
    """Запускает бота и фоновый поток напоминаний."""
    # Поток для поллинга бота
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()

    # Поток для напоминаний
    reminder_thread = threading.Thread(target=reminder_worker, args=(15,), daemon=True)
    reminder_thread.start()

    logger.info("Telegram бот и поток напоминаний запущены")