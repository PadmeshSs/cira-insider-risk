from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> repository root is three levels above "core".
_REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    postgres_user: str = "cira"
    postgres_password: str
    postgres_db: str = "insider_threat_db"

    database_url: str

    environment: str = "development"
    log_level: str = "INFO"

    cert_raw_dir: str = "datasets/raw/cert_r4.2"
    cert_ground_truth_dir: str = "datasets/ground_truth/cert_r4.2"
    cert_source_timezone: str = "UTC"
    cert_target_timezone: str = "UTC"

    # Hardware-Constrained Execution Addendum (HCEA v1.0, §17).
    # Machine-specific absolute paths belong in .env, never in source.
    cert_processed_dir: str = "datasets/processed"
    cira_profile: str = "dev"
    cira_max_workers: int = 6
    cira_chunk_rows: int = 500_000
    cira_max_rss_gb: float = 20.0
    cira_device: str = "auto"
    cira_seed: int = 42

    model_config = SettingsConfigDict(
        # Resolved independently of the current working directory, so the
        # same .env is found from the repo root, backend/, or a test runner.
        # Later entries override earlier ones.
        env_file=(str(_REPO_ROOT / ".env"), ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
