import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.database import get_db
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


def _get_user_by_email(db: sqlite3.Connection, email: str):
    return db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def _get_user_by_id(db: sqlite3.Connection, user_id: int):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(request: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    if _get_user_by_email(db, request.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = get_password_hash(request.password)
    cur = db.execute(
        "INSERT INTO users (email, hashed_password) VALUES (?, ?)",
        (request.email, hashed),
    )
    db.commit()
    user_id = cur.lastrowid

    row = _get_user_by_id(db, user_id)
    if row is None:
        raise HTTPException(status_code=500, detail="Failed to create user")
    return UserResponse(
        id=row["id"],
        email=row["email"],
        created_at=str(row["created_at"]) if row["created_at"] else None,
    )


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    user = _get_user_by_email(db, request.email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(request.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token_data = {"sub": user["email"], "id": user["id"]}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: RefreshRequest, db: sqlite3.Connection = Depends(get_db)):
    payload = decode_and_validate_token(request.refresh_token, expected_type="refresh")
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user = _get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    token_data = {"sub": user["email"], "id": user["id"]}
    new_access = create_access_token(token_data)
    new_refresh = create_refresh_token(token_data)
    return TokenResponse(access_token=new_access, refresh_token=new_refresh, token_type="bearer")


@router.get("/me", response_model=UserResponse)
def read_me(
    payload: dict = Depends(get_current_user_payload),
    db: sqlite3.Connection = Depends(get_db),
):
    email = payload.get("sub")
    user = _get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return UserResponse(
        id=user["id"],
        email=user["email"],
        created_at=str(user["created_at"]) if user["created_at"] else None,
    )
