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
from app.core.config import settings
from app.core.email import send_otp_email
from app.core.otp import create_otp_record, get_active_otp, verify_otp
from app.schemas.auth import (
    AuthRequest,
    AuthResponse,
    LoginRequest,
    OtpSendRequest,
    OtpSendResponse,
    OtpVerifyRequest,
    OtpVerifyResponse,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

router = APIRouter(tags=["auth"])


def _get_user_by_email(db: sqlite3.Connection, email: str):
    return db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def _get_user_by_id(db: sqlite3.Connection, user_id: int):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def _build_user_response(row) -> UserResponse:
    # Be tolerant if older DB rows miss verification columns (migration)
    try:
        is_verified = bool(row["is_email_verified"])
    except Exception:
        is_verified = False
    try:
        verified_at = str(row["email_verified_at"]) if row["email_verified_at"] else None
    except Exception:
        verified_at = None
    return UserResponse(
        id=row["id"],
        email=row["email"],
        created_at=str(row["created_at"]) if row["created_at"] else None,
        is_email_verified=is_verified,
        email_verified_at=verified_at,
    )


def _issue_tokens(user_row) -> tuple[str, str]:
    token_data = {"sub": user_row["email"], "id": user_row["id"]}
    return create_access_token(token_data), create_refresh_token(token_data)


@router.post(
    "/auth",
    response_model=AuthResponse,
    status_code=status.HTTP_200_OK,
    summary="Unified authenticate (register or login)",
    description=(
        "Single endpoint for authentication. If the email does not exist, "
        "a new user is created and `is_new_user=true` is returned so the "
        "frontend can trigger the create-account / complete-profile flow "
        "(e.g. collect address). If the user already exists the password is "
        "verified and tokens are returned with `is_new_user=false`. "
        "Invalid password still returns 401."
    ),
)
def auth(request: AuthRequest, db: sqlite3.Connection = Depends(get_db)):
    """Register if new, otherwise login. Frontend checks `is_new_user` to decide
    whether to show the create-account/profile-completion flow."""
    user = _get_user_by_email(db, request.email)
    is_new_user = False

    if user is None:
        # Register new user
        hashed = get_password_hash(request.password)
        try:
            cur = db.execute(
                "INSERT INTO users (email, hashed_password) VALUES (?, ?)",
                (request.email, hashed),
            )
            db.commit()
        except sqlite3.IntegrityError:
            # Race condition: another request created the user concurrently.
            # Fall back to login path.
            db.rollback()
            user = _get_user_by_email(db, request.email)
            if user is None:
                raise HTTPException(status_code=500, detail="Failed to create user")
            if not verify_password(request.password, user["hashed_password"]):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
                )
            access_token, refresh_token = _issue_tokens(user)
            return AuthResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                is_new_user=False,
                user=_build_user_response(user),
            )

        user_id = cur.lastrowid
        row = _get_user_by_id(db, user_id)
        if row is None:
            raise HTTPException(status_code=500, detail="Failed to create user")
        user = row
        is_new_user = True
    else:
        # Existing user -> verify password (login)
        if not verify_password(request.password, user["hashed_password"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token, refresh_token = _issue_tokens(user)
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        is_new_user=is_new_user,
        user=_build_user_response(user),
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    deprecated=True,
    summary="Deprecated: use POST /auth",
    description="Deprecated. Use `POST /auth` for unified register/login.",
)
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
    return _build_user_response(row)


@router.post(
    "/login",
    response_model=TokenResponse,
    deprecated=True,
    summary="Deprecated: use POST /auth",
    description="Deprecated. Use `POST /auth` for unified register/login. Kept for backward compatibility.",
)
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
    return _build_user_response(user)


# ---------------------------------------------------------------------------
# OTP – email verification
# ---------------------------------------------------------------------------


@router.post("/otp/send", response_model=OtpSendResponse, status_code=status.HTTP_200_OK, tags=["otp"])
def send_otp(request: OtpSendRequest, db: sqlite3.Connection = Depends(get_db)):
    """Generate and email a 6-digit OTP. Valid for `OTP_EXPIRE_MINUTES` (default 10).

    Requires the email to be registered (`POST /auth` first). Gmail SMTP
    is used by default – configure via `SMTP_HOST`, `SMTP_PORT`,
    `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS`.
    """
    user = _get_user_by_email(db, request.email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found. Register via POST /auth first")

    plain_otp, expires_at = create_otp_record(db, request.email)

    sent = send_otp_email(request.email, plain_otp)
    if not sent:
        # Roll back OTP so client can retry
        db.execute("DELETE FROM otps WHERE email = ?", (request.email,))
        db.commit()
        raise HTTPException(status_code=500, detail="Failed to send OTP email. Check SMTP configuration")

    return OtpSendResponse(
        detail="OTP sent to email",
        email=request.email,
        expires_at=expires_at,
        expires_in_minutes=settings.otp_expire_minutes,
    )


@router.post("/otp/verify", response_model=OtpVerifyResponse, status_code=status.HTTP_200_OK, tags=["otp"])
def verify_otp_endpoint(request: OtpVerifyRequest, db: sqlite3.Connection = Depends(get_db)):
    """Verify the OTP. On success marks `is_email_verified=true`.

    OTP is numeric, single-use, expires after 10 minutes and is rate-limited
    by `OTP_MAX_ATTEMPTS` (default 5).
    """
    user = _get_user_by_email(db, request.email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    row = get_active_otp(db, request.email)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP expired or not found. Please request a new one via POST /otp/send",
        )

    if row["attempts"] >= settings.otp_max_attempts:
        db.execute("DELETE FROM otps WHERE email = ?", (request.email,))
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Please request a new OTP",
        )

    if not verify_otp(request.otp, row["otp_hash"]):
        db.execute("UPDATE otps SET attempts = attempts + 1 WHERE id = ?", (row["id"],))
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")

    # Success: mark email verified and remove all OTPs for this email
    db.execute(
        "UPDATE users SET is_email_verified = 1, email_verified_at = CURRENT_TIMESTAMP WHERE email = ?",
        (request.email,),
    )
    db.execute("DELETE FROM otps WHERE email = ?", (request.email,))
    db.commit()

    updated_user = _get_user_by_email(db, request.email)
    if updated_user is None:
        raise HTTPException(status_code=500, detail="Verification succeeded but user not found")

    return OtpVerifyResponse(
        detail="Email verified successfully",
        verified=True,
        user=_build_user_response(updated_user),
    )
