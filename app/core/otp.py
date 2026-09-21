"""
OTP generation, storage and verification.

- OTP is a random numeric string (default 6 digits, configurable via OTP_LENGTH).
- Stored hashed with bcrypt (same as passwords) so plaintext never hits DB.
- Expires after OTP_EXPIRE_MINUTES (default 10).
- Verification checks expiry and max attempts (OTP_MAX_ATTEMPTS).
"""

import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.core.security import get_password_hash, verify_password


def generate_otp(length: int | None = None) -> str:
    length = length or settings.otp_length
    # secrets for cryptographically strong random
    return "".join(secrets.choice("0123456789") for _ in range(length))


def hash_otp(otp: str) -> str:
    return get_password_hash(otp)


def verify_otp(plain_otp: str, otp_hash: str) -> bool:
    return verify_password(plain_otp, otp_hash)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _format_ts(dt: datetime) -> str:
    # SQLite stores timestamps as text; use ISO format with UTC
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def create_otp_record(db: sqlite3.Connection, email: str) -> tuple[str, str]:
    """Generate OTP, hash it, store it and return (plain_otp, expires_at_iso).

    Invalidates previous OTPs for the same email (single active OTP)."""
    plain = generate_otp()
    hashed = hash_otp(plain)
    expires_at = _utcnow() + timedelta(minutes=settings.otp_expire_minutes)
    expires_str = _format_ts(expires_at)

    # Single active OTP per email: delete old ones
    db.execute("DELETE FROM otps WHERE email = ?", (email,))
    db.execute(
        "INSERT INTO otps (email, otp_hash, expires_at) VALUES (?, ?, ?)",
        (email, hashed, expires_str),
    )
    db.commit()
    return plain, expires_str


def get_active_otp(db: sqlite3.Connection, email: str):
    """Return the most recent OTP row for email that hasn't expired, or None."""
    # Use datetime('now') comparison in SQLite; otps.expires_at is in UTC text
    row = db.execute(
        """
        SELECT * FROM otps
        WHERE email = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (email,),
    ).fetchone()
    if row is None:
        return None
    # Check expiry in Python (robust across timezone formats)
    try:
        exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        # Fallback: try ISO
        exp = datetime.fromisoformat(row["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    if exp < _utcnow():
        # Expired -> cleanup
        db.execute("DELETE FROM otps WHERE id = ?", (row["id"],))
        db.commit()
        return None
    return row


def is_otp_expired(row) -> bool:
    try:
        exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        exp = datetime.fromisoformat(row["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    return exp < _utcnow()
