from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


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

    model_config = SettingsConfigDict(
        env_file="../.env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()