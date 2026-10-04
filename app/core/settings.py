from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: str = "development"
    database_url: str = ""
    database_password: SecretStr | None = None
    db_pool_max_size: int = 10
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 10_485_760
    log_level: str = "INFO"
    log_bodies: bool = True
    log_body_max_chars: int = 8000
    audit_body_max_chars: int = 65536

    # Admin API (/api/v1) — JWT Supabase
    supabase_url: str = ""
    supabase_jwt_secret: SecretStr | None = None
    supabase_jwt_audience: str = "authenticated"
    admin_auth_disabled: bool = False
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # Procesy w tle
    listen_notifications: bool = True
    background_jobs: bool = True
    approval_sweep_seconds: float = 2.0
    retention_sweep_seconds: float = 3600.0
    config_reload_debounce_seconds: float = 0.3

    # TypeSafe Jev specialist (optional — NullScorer when unset)
    typesafe_api_key: SecretStr | None = None
    typesafe_model: str = "jev-latest"
    jev_timeout_seconds: float = 0.8

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
