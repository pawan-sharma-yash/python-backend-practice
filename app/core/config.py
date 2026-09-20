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


settings = Settings()
