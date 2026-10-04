from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "MedSync API"
    ENVIRONMENT: str = "development"

    # Segredos: SEM valor padrão. A aplicação não sobe se não vierem do ambiente/.env.
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    DATABASE_URL: str = "sqlite:///./medsync.db"
    ALLOWED_ORIGINS: str = "http://localhost:3000,https://clinica.medsync.com.br"
    LOGIN_RATE_LIMIT_PER_MINUTE: int = 5
    MFA_RATE_LIMIT_PER_MINUTE: int = 5

    # Dados de demonstração (usuários/consultas de exemplo). Desligado por padrão.
    SEED_DEMO_DATA: bool = False
    DEMO_USERS_PASSWORD: Optional[str] = None
    DEMO_LAB_CLIENT_SECRET: Optional[str] = None
    DEMO_ADMIN_MFA_SECRET: Optional[str] = None

    @field_validator("SECRET_KEY")
    @classmethod
    def secret_key_must_be_strong(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY deve ter pelo menos 32 caracteres (use: openssl rand -hex 32).")
        return v

    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()  # type: ignore[call-arg]
