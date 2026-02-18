from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
import asyncio
import os
import shutil
from datetime import datetime
from pathlib import Path
import logging


from . import models, secure_upload, ocr
from .auth import get_current_user
from .database import get_db
from .config import Config

router = APIRouter(prefix="/api/lessons", tags=["lessons"])

UPLOAD_DIR = Path(Config.UPLOAD_FOLDER) / "homework_photos"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

@router.post("/{lesson_id}/upload-homework-photo")
async def upload_homework_photo(
        lesson_id: int,
        file: UploadFile = File(...),
        run_ocr: bool = True,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    """
    Загружает фото выполненного домашнего задания (только для ученика).
    Если run_ocr=True, распознаёт текст и добавляет его в поле homework урока.
    """
    lesson = db.query(models.Lesson).filter(
        models.Lesson.id == lesson_id,
        models.Lesson.user_id == current_user.id
    ).first()
    if not lesson:
        raise HTTPException(status_code=404, detail="Урок не найден")

    try:
        file_bytes, size = await secure_upload.read_file_chunked(file, max_size=5*1024*1024)
    except HTTPException as e:
        raise e

    is_valid_mime, mime_error = secure_upload.validate_file_mime_type(file_bytes, file.filename)
    if not is_valid_mime:
        raise HTTPException(status_code=400, detail=mime_error)

    is_valid_img, img_error = await secure_upload.FileAnomalyDetector.validate_image_content(file_bytes)
    if not is_valid_img:
        raise HTTPException(status_code=400, detail=img_error)

    ext = Path(file.filename).suffix.lower()
    safe_filename = secure_upload.generate_secure_filename(ext)
    file_path = UPLOAD_DIR / safe_filename
    with open(file_path, "wb") as f:
        f.write(file_bytes)

    attachment = models.LessonAttachment(
        lesson_id=lesson.id,
        file_path=str(file_path),
        original_filename=file.filename,
        mime_type=file.content_type,
        file_size=size
    )
    db.add(attachment)

    if run_ocr:
        try:
            recognized_text = await asyncio.to_thread(ocr.extract_text_from_image, file_bytes)
            if recognized_text:
                if lesson.homework:
                    lesson.homework += f"\n\n[Распознано с фото]: {recognized_text}"
                else:
                    lesson.homework = recognized_text
        except Exception as e:
            logging.error(f"OCR error: {e}")

    db.commit()

    return {
        "success": True,
        "attachment_id": attachment.id,
        "recognized_text": recognized_text if run_ocr else None
    }