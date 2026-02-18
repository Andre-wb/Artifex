from groq import Groq
from .config import Config
import logging

logger = logging.getLogger(__name__)

# Проверяем наличие API ключа
if not Config.API_KEY:
    logger.error("GROQ_API_KEY не найден в переменных окружения")
    raise ValueError("GROQ_API_KEY не установлен")

client = Groq(api_key=Config.API_KEY)
MODEL = "llama-3.3-70b-versatile"

SYSTEM_PROMPTS = {
    "explain_homework": (
        "Ты — помощник-репетитор. Объясняй задачу ясно и кратко, по возможности в несколько предложений. "
        "Ты должен объяснить задачу максимально вежливо и точно. Если пользователь просит тебя дать ответ, "
        "ты дашь ответ, но при этом ты должен доходчиво объяснить как его получить. "
        "Не отвлекайся на другие задачи. Ответ напиши на русском языке, дружелюбно и поддерживающе."
    ),
    "break_down_task": (
        "Ты — помощник по планированию. Разбей задачу на 3–5 простых шагов. "
        "Ответь строго в формате JSON: {\"steps\": [\"шаг1\", \"шаг2\", ...]}. Не добавляй пояснений. Ответ напиши на русском языке, дружелюбно и поддерживающе."
    ),
    "mood_advice": (
        "Ты — эмпатичный помощник по улучшению эмоционального состояния. "
        "Пользователь описал своё состояние или проблему. Дай добрый, короткий и практичный совет, "
        "как справиться с этой ситуацией или улучшить настроение. Не ставь медицинских диагнозов. "
        "Если комментарий неясен, вежливо попроси уточнить. Ответ напиши на русском языке, дружелюбно и поддерживающе."
    ),
    "general_help": (
        "Ты — полезный ассистент. Отвечай на вопросы пользователя вежливо, точно и по существу. "
        "Если вопрос не относится к школьной тематике, старайся помочь в рамках общих знаний. Ответ напиши на русском языке, дружелюбно и поддерживающе."
    )
}

def ask_support(prompt: str, task_type: str = "explain_homework") -> str:
    """
    Отправляет запрос в Groq API с выбором системного промпта в зависимости от типа задачи.

    Аргументы:
        prompt: пользовательский ввод (текст задачи или вопроса)
        task_type: тип задачи, определяющий системный промпт.
                   Допустимые значения: 'explain_homework', 'break_down_task', 'mood_advice', 'general_help'.

    Возвращает:
        Ответ от модели (текст).
    """
    if not prompt or not prompt.strip():
        return "Пожалуйста, задайте вопрос."

    system_prompt = SYSTEM_PROMPTS.get(task_type, SYSTEM_PROMPTS["general_help"])

    try:
        logger.info(f"Отправка запроса к Groq API. Тип задачи: {task_type}")

        chat_completion = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1024
        )

        response = chat_completion.choices[0].message.content
        logger.info("Успешно получен ответ от Groq API")
        return response

    except Exception as e:
        error_msg = f"Ошибка при обращении к AI: {str(e)}"
        logger.error(error_msg, exc_info=True)

        # Возвращаем дружественное сообщение пользователю
        if "403" in str(e):
            return "Извините, возникла проблема с доступом к AI сервису. Пожалуйста, попробуйте позже или обратитесь к администратору."
        elif "rate limit" in str(e).lower():
            return "Превышен лимит запросов к AI. Пожалуйста, подождите немного и попробуйте снова."
        else:
            return "Извините, не удалось получить ответ от AI. Пожалуйста, попробуйте позже."