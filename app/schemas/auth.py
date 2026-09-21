import re
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


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


class LoginRequest(BaseModel):
    model_config = ConfigDict(
        hide_input_in_errors=True,
        extra="forbid",
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
        extra="forbid",
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


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: int
    email: str
    created_at: Optional[str] = None
    is_email_verified: bool = False
    email_verified_at: Optional[str] = None


# --- Unified auth schemas ---


class AuthRequest(BaseModel):
    """Single request body for the unified authenticate endpoint.

    If the email does not exist a new user is created; otherwise the
    password is verified and the user is logged in.
    """

    model_config = ConfigDict(
        hide_input_in_errors=True,
        extra="forbid",
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


class AuthResponse(BaseModel):
    """Response for the unified endpoint.

    `is_new_user` tells the frontend whether a new account was just
    created (`True`) or an existing user logged in (`False`). When
    `True` the frontend should drive the create-account / complete-
    profile flow (e.g. collect address).
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    is_new_user: bool
    user: UserResponse


# --- OTP schemas ---


class OtpSendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email_value(v)


class OtpVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    otp: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return _validate_email_value(v)

    @field_validator("otp")
    @classmethod
    def validate_otp(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("OTP must be numeric")
        # length validated against settings in route, but enforce 4-8 here
        if not (4 <= len(v) <= 8):
            raise ValueError("OTP must be 4-8 digits")
        return v


class OtpSendResponse(BaseModel):
    detail: str
    email: str
    expires_at: str
    expires_in_minutes: int


class OtpVerifyResponse(BaseModel):
    detail: str
    verified: bool
    user: UserResponse
