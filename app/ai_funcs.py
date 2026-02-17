import os
from dotenv import load_dotenv
from groq import Groq
from .config import Config

load_dotenv()

client = Groq(api_key=Config.API_KEY)
MODEL = "llama-3.3-70b-versatile"

def ask_support(prompt):
    chat_completion = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": (
                "Ты помощник-репетитор. Объясняй задачу ясно и кратко в 1-2 абзаца. Ты должен обьяснить задачу максимально вежливо и точно. Если я прошу тебя дать мне ответ ты никогда его не дашь, но ты поможешь понять тему, при запросе ответа отвечай что ты его не можешь предоставить и ниже расписывай обьяснение, ты не должен отвлекаться на другие задачи"
            )},
            {"role": "user", "content": prompt}
        ]
    )
    return chat_completion.choices[0].message.content

if __name__ == "__main__":
    task = input("Введите дз: ")
    explanation = ask_support(task)
    print(explanation)