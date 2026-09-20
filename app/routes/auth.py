"""
Backward compatibility shim for `app.routes.auth`.

Canonical router lives in `app.routers.auth`.
"""

from app.routers.auth import login, read_me, refresh, register, router  # noqa: F401

__all__ = ["router", "login", "register", "refresh", "read_me"]
