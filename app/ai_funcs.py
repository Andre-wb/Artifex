import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
API_KEY = os.getenv("GROQ_API_KEY")

client = Groq(api_key=API_KEY)
MODEL = "llama-3.3-70b-versatile"

def ask_support(prompt):
    chat_completion = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": (
                "Ты помощник-репетитор. Объясняй задачу ясно и кратко в 1-2 абзаца. Ты должен обьяснить задачу максимально вежливо и точно."
            )},
            {"role": "user", "content": prompt}
        ]
    )
    return chat_completion.choices[0].message.content

if __name__ == "__main__":
    task = input("Введите дз: ")
    explanation = ask_support(task)
    print(explanation)
