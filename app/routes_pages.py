"""
Модуль для простых HTML-страниц (домашняя, расписание, рейтинг).
Не содержит сложной логики, только рендеринг шаблонов.
"""

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Subject, TimetableTemplate, Group, GroupMember
from app.auth import get_current_user
from app.templates import templates

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """
    Главная страница.
    """
    return RedirectResponse(url="/diary")


@router.get("/timetable", response_class=HTMLResponse)
async def timetable(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Страница с шаблоном расписания (редактирование).
    """
    subjects = db.query(Subject).all()
    timetable_templates = db.query(TimetableTemplate).filter(
        TimetableTemplate.user_id == current_user.id
    ).order_by(TimetableTemplate.day_of_week, TimetableTemplate.lesson_number).all()

    return templates.TemplateResponse(
        "timetable.html",
        {
            "request": request,
            "user": current_user,
            "subjects": subjects,
            "templates": timetable_templates,
            "weekdays": ['Понедельник', 'Вторник', 'Среда', 'Четверг', 'Пятница', 'Суббота', 'Воскресенье']
        }
    )


@router.get("/rating", response_class=HTMLResponse)
async def rating(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Страница с рейтингом (таблица лидеров).
    """
    return templates.TemplateResponse(
        "rating.html",
        {
            "request": request,
            "user": current_user
        }
    )


@router.get("/teacher/groups", response_class=HTMLResponse)
async def teacher_groups(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Страница управления группами для учителя.
    """
    if not current_user.is_teacher:
        return RedirectResponse(url="/diary")

    groups = db.query(Group).filter(Group.teacher_id == current_user.id).all()
    for group in groups:
        group.members_count = db.query(GroupMember).filter(GroupMember.group_id == group.id).count()

    return templates.TemplateResponse(
        "teacher_groups.html",
        {
            "request": request,
            "user": current_user,
            "groups": groups
        }
    )


@router.get("/teacher/students", response_class=HTMLResponse)
async def teacher_students(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Страница со списком учеников для учителя.
    """
    if not current_user.is_teacher:
        return RedirectResponse(url="/diary")

    # Получаем всех учеников этого учителя
    students = db.query(User).filter(
        User.teacher_id == current_user.id,
        User.is_teacher == False
    ).all()

    # Получаем группы учителя
    groups = db.query(Group).filter(Group.teacher_id == current_user.id).all()
    groups_dict = {g.id: g.name for g in groups}

    # Для каждого ученика получаем его группу
    for student in students:
        membership = db.query(GroupMember).filter(
            GroupMember.user_id == student.id,
            GroupMember.group_id.in_([g.id for g in groups])
        ).first()
        student.group_name = groups_dict.get(membership.group_id, "Не в группе") if membership else "Не в группе"

    return templates.TemplateResponse(
        "teacher_students.html",
        {
            "request": request,
            "user": current_user,
            "students": students
        }
    )


@router.get("/teacher/student/{student_id}", response_class=HTMLResponse)
async def teacher_student_detail(
        request: Request,
        student_id: int,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Страница с детальной информацией об ученике для учителя.
    """
    if not current_user.is_teacher:
        return RedirectResponse(url="/diary")

    student = db.query(User).filter(
        User.id == student_id,
        User.teacher_id == current_user.id,
        User.is_teacher == False
    ).first()

    if not student:
        return RedirectResponse(url="/teacher/students")

    return templates.TemplateResponse(
        "teacher_student_detail.html",
        {
            "request": request,
            "user": current_user,
            "student": student
        }
    )


@router.get("/my-groups", response_class=HTMLResponse)
async def my_groups(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Страница с группами ученика.
    """
    if current_user.is_teacher:
        return RedirectResponse(url="/teacher/groups")

    memberships = db.query(GroupMember).filter(
        GroupMember.user_id == current_user.id
    ).all()

    groups = []
    for membership in memberships:
        group = membership.group
        group.members_count = db.query(GroupMember).filter(GroupMember.group_id == group.id).count()
        groups.append(group)

    return templates.TemplateResponse(
        "my_groups.html",
        {
            "request": request,
            "user": current_user,
            "groups": groups
        }
    )


@router.get("/stats", response_class=HTMLResponse)
async def stats_page(
        request: Request,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    """
    Страница со статистикой успеваемости.
    """
    return templates.TemplateResponse(
        "stats.html",
        {
            "request": request,
            "user": current_user
        }
    )