from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "MedSync API"
    ENVIRONMENT: str = "development"
    SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    MFA_SECRET_DEV: str = "849201"
    DATABASE_URL: str = "sqlite:///./medsync.db"
    ALLOWED_ORIGINS: str = "http://localhost:3000,https://clinica.medsync.com.br"
    LOGIN_RATE_LIMIT_PER_MINUTE: int = 5

    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
