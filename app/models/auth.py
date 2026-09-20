"""
Re-export for backward compatibility.

Canonical schema lives in `app.schemas.auth`.
Existing imports `from app.models.auth import LoginRequest` keep working.
"""

from app.schemas.auth import (  # noqa: F401
    LoginRequest,
    LoginRequestLegacy,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

__all__ = [
    "LoginRequest",
    "LoginRequestLegacy",
    "RegisterRequest",
    "TokenResponse",
    "RefreshRequest",
    "UserResponse",
]
