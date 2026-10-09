from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_prefix="PURPLELAB_",
        extra="ignore",
    )

    app_name: str = "PurpleLab"
    environment: str = "development"
    debug: bool = True
    database_url: str = "postgresql+asyncpg://purplelab:purplelab@localhost:5432/purplelab"
    database_url_sync: str = "postgresql://purplelab:purplelab@localhost:5432/purplelab"
    lab_allowlist: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost", "lab.internal"])
    execution_timeout_seconds: int = Field(default=60, ge=1, le=600)
    max_events_per_execution: int = Field(default=500, ge=1, le=10000)
    require_approval: bool = False
    default_collector: str = "fixture"
    fixture_path: Path = PROJECT_ROOT / "fixtures"
    scenarios_dir: Path = PROJECT_ROOT / "scenarios"
    rules_dir: Path = PROJECT_ROOT / "rules" / "sigma"
    siem_endpoint: str | None = None
    siem_api_key: str | None = None
    elastic_endpoint: str | None = None
    elastic_api_key: str | None = None
    elastic_events_index: str = "logs-*"
    elastic_alerts_index: str = ".alerts-security.alerts-*"
    splunk_endpoint: str | None = None
    splunk_token: str | None = None
    sentinel_workspace_id: str | None = None
    sentinel_token: str | None = None
    sentinel_endpoint: str = "https://api.loganalytics.io/v1"
    sysmon_evtx_path: Path | None = None
    zeek_log_dir: Path | None = None
    suricata_eve_path: Path | None = None
    collector_verify_tls: bool = True
    collector_timeout_seconds: int = Field(default=20, ge=1, le=120)
    max_collector_events: int = Field(default=500, ge=1, le=5000)
    default_latency_window_seconds: int = Field(default=30, ge=1, le=3600)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()