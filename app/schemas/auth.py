import re
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


def _validate_email_value(v: str) -> str:
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, v):
        raise ValueError("Invalid email address")
    return v


def _validate_password_value(v: str) -> str:
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"[0-9]", v):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\\/\[\];'`~+=]", v):
        raise ValueError("Password must contain at least one special character")
    return v


def _validate_username_value(v: str) -> str:
    if len(v) < 3:
        raise ValueError("Username must be at least 3 characters long")
    if len(v) > 50:
        raise ValueError("Username must be at most 50 characters long")
    if not re.match(r"^[a-zA-Z0-9._-]+$", v):
        raise ValueError("Username can only contain alphanumeric characters, dots, underscores and hyphens")
    return v


class LoginRequest(BaseModel):
    model_config = ConfigDict(
        hide_input_in_errors=True,
    )

    email: Optional[str] = None
    username: Optional[str] = None
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _validate_email_value(v)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _validate_username_value(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_value(v)

    @model_validator(mode="after")
    def check_identifier(self):
        if self.email is None and self.username is None:
            raise ValueError("Either email or username must be provided")
        return self


# Legacy alias - keep strict email-only for backward compat if needed internally
class LoginRequestLegacy(BaseModel):
    model_config = ConfigDict(
        hide_input_in_errors=True,
    )
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email_value(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_value(v)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(
        hide_input_in_errors=True,
    )

    username: str
    email: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return _validate_username_value(v)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email_value(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_value(v)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: Optional[str] = None
