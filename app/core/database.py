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


def init_db(db_path: str | None = None) -> None:
    """Create users table if not exists."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
        # Create indexes for fast lookup
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.commit()
    finally:
        conn.close()


def _ensure_users_table(conn: sqlite3.Connection) -> None:
    """Ensure users table exists on the given connection."""
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.commit()
    except Exception:
        pass


def get_db():
    """FastAPI dependency that yields a DB connection."""
    conn = get_connection()
    _ensure_users_table(conn)
    try:
        yield conn
    finally:
        conn.close()
