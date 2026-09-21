import os

from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "Kalikiri Backend"
    version: str = "1.0.0"
    debug: bool = False
    # JWT settings
    secret_key: str = os.getenv("JWT_SECRET_KEY", "change-this-secret-key-in-production-please")
    algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    refresh_token_expire_days: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    # Database
    database_path: str = os.getenv("DATABASE_PATH", "./kalikiri.db")
    # SMTP / Email (Gmail by default, configurable via env)
    smtp_host: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", ""))
    smtp_tls: bool = os.getenv("SMTP_TLS", "true").lower() in ("1", "true", "yes")
    smtp_timeout: int = int(os.getenv("SMTP_TIMEOUT", "10"))
    # OTP
    otp_expire_minutes: int = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
    otp_length: int = int(os.getenv("OTP_LENGTH", "6"))
    otp_max_attempts: int = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))


settings = Settings()
