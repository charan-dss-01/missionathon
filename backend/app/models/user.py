from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pydantic import BaseModel, EmailStr, Field, field_validator
import re

class UserRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Full user name")
    email: EmailStr = Field(..., description="Corporate or personal email address")
    password: str = Field(..., min_length=8, max_length=128, description="Account password")

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[a-zA-Z]", v) or not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one letter and one number.")
        return v

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("New password must be at least 8 characters long.")
        if not re.search(r"[a-zA-Z]", v) or not re.search(r"[0-9]", v):
            raise ValueError("New password must contain at least one letter and one number.")
        return v

class UserProfileResponse(BaseModel):
    id: str
    name: str
    email: str
    role: str = "user" # user, admin, soc_analyst
    status: str = "active"
    created_at: datetime
    last_login: Optional[datetime] = None

class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfileResponse

class AuditRecord(BaseModel):
    id: str
    user_id: Optional[str] = None
    event_type: str # LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, REGISTER, PASSWORD_CHANGE
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
