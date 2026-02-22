"""Application configuration using pydantic-settings."""

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = "sqlite+aiosqlite:///./scanner.db"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # App
    secret_key: str = "dev-secret-key-change-in-production"
    debug: bool = True
    allowed_origins: str = "http://localhost:3000,http://localhost:5173"

    # Scan limits
    scan_timeout_seconds: int = 300
    max_concurrent_scans: int = 5
    rate_limit_per_minute: int = 30

    # Repo cloning
    max_repo_size_mb: int = 500
    clone_depth: int = 1

    # GitHub API
    github_token: Optional[str] = None
    github_api_timeout: int = 30

    # Gemini AI
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.0-flash"

    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.allowed_origins.split(",")]

    @property
    def is_postgres(self) -> bool:
        return "postgresql" in self.database_url

    @property
    def sync_database_url(self) -> str:
        """Return a synchronous database URL for Alembic / RQ workers."""
        return self.database_url.replace("+asyncpg", "").replace("+aiosqlite", "").replace("+psycopg", "")


settings = Settings()
