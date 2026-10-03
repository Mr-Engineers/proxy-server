from functools import lru_cache

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
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 10_485_760


@lru_cache
def get_settings() -> Settings:
    return Settings()
