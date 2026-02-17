from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Date, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from .database import Base

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    phone = Column(String(20), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    confirmed = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    locked_until = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    xp = Column(Integer, default=0, nullable=False)
    level = Column(Integer, default=1, nullable=False)
    league = Column(String(20), default='Bronze', nullable=False)
    streak_days = Column(Integer, default=0, nullable=False)
    last_streak_date = Column(Date, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Связи
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    lessons = relationship("Lesson", back_populates="user", cascade="all, delete-orphan")
    grades = relationship("Grade", back_populates="user", cascade="all, delete-orphan")
    timetable_templates = relationship("TimetableTemplate", back_populates="user", cascade="all, delete-orphan")
    achievements = relationship("UserAchievement", back_populates="user", cascade="all, delete-orphan")

class RefreshToken(Base):
    __tablename__ = 'refresh_tokens'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_agent = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)

    user = relationship("User", back_populates="refresh_tokens")

class Subject(Base):
    __tablename__ = 'subjects'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    teacher_name = Column(String(200), nullable=True)
    color = Column(String(7), default='#3498db')
    created_at = Column(DateTime, default=datetime.utcnow)

    lessons = relationship("Lesson", back_populates="subject", cascade="all, delete-orphan")
    grades = relationship("Grade", back_populates="subject", cascade="all, delete-orphan")

class Lesson(Base):
    __tablename__ = 'lessons'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    subject_id = Column(Integer, ForeignKey('subjects.id'), nullable=False)
    date = Column(Date, nullable=False)
    lesson_number = Column(Integer, nullable=False)
    start_time = Column(String(5), nullable=True)
    end_time = Column(String(5), nullable=True)
    room = Column(String(50), nullable=True)
    homework = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    student_completed = Column(Boolean, default=False, nullable=False)
    student_completed_at = Column(DateTime, nullable=True)
    teacher_confirmed = Column(Boolean, default=False, nullable=False)
    teacher_confirmed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="lessons")
    subject = relationship("Subject", back_populates="lessons")
    grades = relationship("Grade", back_populates="lesson", cascade="all, delete-orphan")

class Grade(Base):
    __tablename__ = 'grades'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    subject_id = Column(Integer, ForeignKey('subjects.id'), nullable=False)
    lesson_id = Column(Integer, ForeignKey('lessons.id'), nullable=True)
    value = Column(Integer, nullable=False)
    weight = Column(Float, default=1.0)
    date = Column(Date, nullable=False)
    description = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="grades")
    subject = relationship("Subject", back_populates="grades")
    lesson = relationship("Lesson", back_populates="grades")

class TimetableTemplate(Base):
    __tablename__ = 'timetable_templates'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    day_of_week = Column(Integer, nullable=False)
    lesson_number = Column(Integer, nullable=False)
    subject_id = Column(Integer, ForeignKey('subjects.id'), nullable=False)
    start_time = Column(String(5), nullable=True)
    end_time = Column(String(5), nullable=True)
    room = Column(String(50), nullable=True)

    user = relationship("User", back_populates="timetable_templates")
    subject = relationship("Subject")

class Achievement(Base):
    __tablename__ = 'achievements'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255), nullable=False)
    condition_type = Column(String(50), nullable=False)
    condition_value = Column(Integer, nullable=False)
    icon = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Связь с пользователями
    users = relationship("UserAchievement", back_populates="achievement", cascade="all, delete-orphan")


class UserAchievement(Base):
    __tablename__ = 'user_achievements'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    achievement_id = Column(Integer, ForeignKey('achievements.id'), nullable=False)
    earned_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="achievements")
    achievement = relationship("Achievement", back_populates="users")