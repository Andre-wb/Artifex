from datetime import date, time
from typing import Optional, List, Dict, ForwardRef
from pydantic import BaseModel, EmailStr, validator
import re
from datetime import datetime
from .security import validate_password

# Forward references для решения циклических зависимостей
GradeResponse = ForwardRef('GradeResponse')
LessonResponse = ForwardRef('LessonResponse')

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    phone: str
    password: str
    confirm: str
    class Config:
        extra = 'forbid'

    @validator('phone')
    def validate_phone(cls, v):
        normalized = re.sub(r'\D', '', v)
        if not re.match(r'^[1-9]\d{7,14}$', normalized):
            raise ValueError('Некорректный формат телефона')
        return normalized

    @validator('confirm')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Пароли не совпадают')
        return v

    @validator('password')
    def validate_password(cls, v):
        is_valid, error_message = validate_password(v)
        if not is_valid:
            raise ValueError(error_message)
        return v

class UserLogin(BaseModel):
    credential: str
    password: str
    class Config:
        extra = 'forbid'

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    phone: str
    confirmed: bool
    is_admin: bool
    created_at: datetime
    class Config:
        extra = 'forbid'
        from_attributes = True

class SubjectBase(BaseModel):
    name: str
    teacher_name: Optional[str] = None
    color: Optional[str] = '#3498db'

class SubjectCreate(SubjectBase):
    pass

class SubjectResponse(SubjectBase):
    id: int
    created_at: datetime
    class Config:
        from_attributes = True

class LessonBase(BaseModel):
    subject_id: int
    date: date
    lesson_number: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    room: Optional[str] = None
    homework: Optional[str] = None
    notes: Optional[str] = None

class LessonCreate(LessonBase):
    pass

class LessonUpdate(BaseModel):
    subject_id: Optional[int] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    room: Optional[str] = None
    homework: Optional[str] = None
    notes: Optional[str] = None

class GradeBase(BaseModel):
    subject_id: int
    value: int
    weight: float = 1.0
    date: date
    description: Optional[str] = None
    lesson_id: Optional[int] = None

class GradeCreate(GradeBase):
    pass

class GradeUpdate(BaseModel):
    value: Optional[int] = None
    weight: Optional[float] = None
    description: Optional[str] = None

class GradeResponse(GradeBase):
    id: int
    user_id: int
    created_at: datetime
    subject: SubjectResponse
    lesson: Optional['LessonResponse'] = None
    class Config:
        from_attributes = True

class LessonResponse(LessonBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime
    subject: SubjectResponse
    grades: List[GradeResponse] = []
    class Config:
        from_attributes = True

class SubjectAverage(BaseModel):
    subject_id: int
    subject_name: str
    average: float
    grades_count: int
    color: str

class DayStats(BaseModel):
    date: date
    lessons_count: int
    grades_count: int
    average: Optional[float] = None

class TimetableTemplateBase(BaseModel):
    day_of_week: int
    lesson_number: int
    subject_id: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    room: Optional[str] = None

class TimetableTemplateCreate(TimetableTemplateBase):
    pass

class TimetableTemplateResponse(TimetableTemplateBase):
    id: int
    user_id: int
    subject: SubjectResponse
    class Config:
        from_attributes = True

class UserAchievementOut(BaseModel):
    id: int
    achievement_id: int
    achievement_name: str
    achievement_description: str
    achievement_icon: Optional[str]
    earned_at: datetime

    class Config:
        from_attributes = True


class GamificationProfileOut(BaseModel):
    xp: int
    level: int
    league: str
    streak_days: int
    recent_achievements: List[UserAchievementOut]

    class Config:
        from_attributes = True


class AchievementOut(BaseModel):
    id: int
    name: str
    description: str
    condition_type: str
    condition_value: int
    icon: Optional[str]

    class Config:
        from_attributes = True


class AchievementWithEarnedOut(AchievementOut):
    earned: bool
    earned_at: Optional[datetime]

    class Config:
        from_attributes = True


class LeaderboardEntryOut(BaseModel):
    user_id: int
    username: str
    xp: int
    level: int
    league: str

    class Config:
        from_attributes = True

class HomeworkHelpRequest(BaseModel):
    lesson_id: int

class AIRequest(BaseModel):
    lesson_id: Optional[int] = None
    text: Optional[str] = None

GradeResponse.model_rebuild()
LessonResponse.model_rebuild()