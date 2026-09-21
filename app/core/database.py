"""
SQLite database configuration for user authentication.
"""

import os
import sqlite3
from pathlib import Path

from app.core.config import settings


def get_database_path() -> str:
    return settings.database_path


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or get_database_path()
    # Ensure directory exists
    dir_name = os.path.dirname(path)
    if dir_name:
        Path(dir_name).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate_users_table(conn: sqlite3.Connection) -> None:
    """Add verification columns if they don't exist (SQLite no IF NOT EXISTS for columns)."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "is_email_verified" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN is_email_verified INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    if "email_verified_at" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP")
        conn.commit()


def _ensure_otps_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.execute("CREATE INDEX IF NOT EXISTS idx_otps_email ON otps(email)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_otps_expires ON otps(expires_at)")
    conn.commit()
    # Cleanup expired OTPs opportunistically
    try:
        conn.execute("DELETE FROM otps WHERE expires_at < CURRENT_TIMESTAMP")
        conn.commit()
    except Exception:
        pass


def init_db(db_path: str | None = None) -> None:
    """Create users + otps tables if not exists."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_email_verified INTEGER NOT NULL DEFAULT 0,
                email_verified_at TIMESTAMP
            )
            """
        )
        conn.commit()
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.commit()
        _migrate_users_table(conn)
        _ensure_otps_table(conn)
    finally:
        conn.close()


def _ensure_users_table(conn: sqlite3.Connection) -> None:
    """Ensure users + otps tables exist on the given connection."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_email_verified INTEGER NOT NULL DEFAULT 0,
            email_verified_at TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    conn.commit()
    _migrate_users_table(conn)
    _ensure_otps_table(conn)


def get_db():
    """FastAPI dependency that yields a DB connection."""
    conn = get_connection()
    _ensure_users_table(conn)
    try:
        yield conn
    finally:
        conn.close()
