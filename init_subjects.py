# технический скрипит для добавления предметов
from app.database import SessionLocal
from app.models import Subject

db = SessionLocal()

# Проверяем, есть ли уже предметы
if db.query(Subject).count() == 0:
    default_subjects = [
        {"name": "Математика", "teacher_name": "Иванова М.И.", "color": "#e74c3c"},
        {"name": "Русский язык", "teacher_name": "Петрова А.С.", "color": "#3498db"},
        {"name": "Литература", "teacher_name": "Сидорова Е.В.", "color": "#9b59b6"},
        {"name": "Физика", "teacher_name": "Козлов П.А.", "color": "#f39c12"},
        {"name": "Химия", "teacher_name": "Смирнова О.Н.", "color": "#2ecc71"},
        {"name": "История", "teacher_name": "Васильев И.И.", "color": "#e67e22"},
        {"name": "Английский язык", "teacher_name": "Морозова Т.В.", "color": "#1abc9c"},
        {"name": "Физкультура", "teacher_name": "Сидоров А.А.", "color": "#27ae60"},
        {"name": "Информатика", "teacher_name": "Волков Д.Н.", "color": "#8e44ad"},
    ]

    for subject_data in default_subjects:
        subject = Subject(**subject_data)
        db.add(subject)

    db.commit()
    print("✅ Базовые предметы добавлены!")
else:
    print("ℹ️ Предметы уже существуют в базе")

db.close()