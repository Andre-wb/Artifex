import ssl
import certifi
ssl._create_default_https_context = ssl.create_default_context(cafile=certifi.where())

import io
import easyocr
from PIL import Image

# глобальный OCR-движок, чтобы не грузился заново на каждый запрос
reader = easyocr.Reader(['en', 'ru'])

def extract_text_from_image(image_bytes: bytes) -> str:
    """
    Распознаёт текст из изображения (байты).
    Возвращает распознанный текст строкой.
    """
    image = Image.open(io.BytesIO(image_bytes))
    results = reader.readtext(image, detail=0)
    return "\n".join(results).strip()
