from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Sentinel"
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@db:5432/sentinel"
    openai_api_key: str | None = None
    openai_model: str = "gpt-5.6"
    llm_enabled: bool = True
    llm_max_concurrency: int = 3
    llm_timeout_seconds: float = 90.0
    llm_max_retries: int = 3
    llm_max_context_chars: int = 40_000
    max_llm_candidates: int = 30
    max_patch_bytes: int = 64_000
    max_patch_changed_lines: int = 200
    data_dir: Path = Path("/data")
    allowed_git_hosts: list[str] = ["github.com", "gitlab.com", "bitbucket.org"]
    max_archive_bytes: int = 50 * 1024 * 1024
    max_extracted_bytes: int = 200 * 1024 * 1024
    max_archive_files: int = 5000
    max_source_file_bytes: int = 1_000_000

    @field_validator("allowed_git_hosts", mode="before")
    @classmethod
    def split_hosts(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"


@lru_cache
def get_settings() -> Settings:
    return Settings()
