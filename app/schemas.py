from pydantic import BaseModel, EmailStr, validator
from typing import Optional, Dict, List
import re
from datetime import datetime
from .security import validate_password

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