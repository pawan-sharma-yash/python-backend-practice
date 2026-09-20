import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.database import get_db, init_db
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_and_validate_token,
    get_current_user_payload,
    get_password_hash,
    verify_password,
)
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse, UserResponse

router = APIRouter(tags=["auth"])

# Ensure table exists on first import (helps for tests without lifespan)
try:
    init_db()
except Exception:
    pass


def _get_user_by_email(db: sqlite3.Connection, email: str):
    return db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def _get_user_by_username(db: sqlite3.Connection, username: str):
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def _get_user_by_id(db: sqlite3.Connection, user_id: int):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@router.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
def register(request: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # Ensure table exists on the provided connection (handles in-memory DBs in tests)
    try:
        db.execute(
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
        db.commit()
    except Exception:
        pass

    # Check duplicates
    if _get_user_by_username(db, request.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    if _get_user_by_email(db, request.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = get_password_hash(request.password)
    try:
        cur = db.execute(
            "INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)",
            (request.username, request.email, hashed),
        )
        db.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError as e:
        # Race condition fallback
        raise HTTPException(status_code=400, detail="Username or email already registered") from e

    row = _get_user_by_id(db, user_id)
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create user")
    return UserResponse(
        id=row["id"],
        username=row["username"],
        email=row["email"],
        created_at=str(row["created_at"]) if row["created_at"] else None,
    )


@router.post("/login", response_model=TokenResponse)
@router.post("/auth/login", response_model=TokenResponse, include_in_schema=False)
def login(request: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    # Resolve user by email or username
    user = None
    identifier = None

    # Prefer email if provided
    if request.email:
        user = _get_user_by_email(db, request.email)
        identifier = request.email
    if user is None and request.username:
        user = _get_user_by_username(db, request.username)
        identifier = request.username
    # Fallback: if only one identifier provided but not found, try the other field (handles legacy)
    if user is None and request.email and not request.username:
        # try username lookup with email value (in case user sent username as email? no)
        pass
    if user is None and request.username and not request.email:
        # try email lookup with username value
        user_try = _get_user_by_email(db, request.username)
        if user_try:
            user = user_try

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(request.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Create tokens; sub = username (unique) ; also store email and id for convenience
    token_data = {"sub": user["username"], "email": user["email"], "id": user["id"]}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@router.post("/refresh", response_model=TokenResponse)
@router.post("/auth/refresh", response_model=TokenResponse, include_in_schema=False)
def refresh(request: RefreshRequest, db: sqlite3.Connection = Depends(get_db)):
    payload = decode_and_validate_token(request.refresh_token, expected_type="refresh")
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Fetch user to ensure still exists
    user = _get_user_by_username(db, username)
    if user is None:
        # Try by id
        try:
            user = _get_user_by_id(db, int(username))
        except Exception:
            pass
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    token_data = {"sub": user["username"], "email": user["email"], "id": user["id"]}
    new_access = create_access_token(token_data)
    # Optionally rotate refresh token as well
    new_refresh = create_refresh_token(token_data)
    return TokenResponse(access_token=new_access, refresh_token=new_refresh, token_type="bearer")


@router.get("/me", response_model=UserResponse)
@router.get("/auth/me", response_model=UserResponse, include_in_schema=False)
def read_me(
    payload: dict = Depends(get_current_user_payload),
    db: sqlite3.Connection = Depends(get_db),
):
    username = payload.get("sub")
    user = _get_user_by_username(db, username)
    if user is None:
        try:
            user = _get_user_by_id(db, int(username))
        except Exception:
            pass
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        created_at=str(user["created_at"]) if user["created_at"] else None,
    )


# Optional alternative route for compatibility: /auth/me and /users/me style
@router.get("/users/me", response_model=UserResponse)
def read_users_me(
    payload: dict = Depends(get_current_user_payload),
    db: sqlite3.Connection = Depends(get_db),
):
    return read_me(payload, db)
