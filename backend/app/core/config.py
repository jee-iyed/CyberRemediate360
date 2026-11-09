"""Application configuration loaded from environment variables (prefix ``CR360_``).

Every value has a safe default for the offline demo. Nothing secret is hard-coded:
the optional API key is only read from the environment or a local ``.env`` file.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "cyberremediate.db"


class ScoringConfig(BaseModel):
    """Weights of the internal priority score (sum of the maxima = 100).

    See docs/risk_scoring.md for the rationale of each weight.
    """

    severity_max: float = 50.0  # CVSS base score / 10 * severity_max
    exposure_internet: float = 20.0
    exposure_internal: float = 8.0
    exposure_isolated: float = 0.0
    criticality_critical: float = 15.0
    criticality_high: float = 10.0
    criticality_medium: float = 5.0
    criticality_low: float = 0.0
    threat_kev: float = 15.0  # listed in CISA KEV (verified source required)
    threat_epss_high: float = 10.0  # EPSS >= epss_high_threshold
    threat_epss_medium: float = 5.0  # EPSS >= epss_medium_threshold
    threat_max: float = 15.0  # KEV and EPSS overlap: the threat component is capped
    epss_high_threshold: float = 0.5
    epss_medium_threshold: float = 0.1
    p1_threshold: float = 75.0
    p2_threshold: float = 55.0
    p3_threshold: float = 35.0


class SlaConfig(BaseModel):
    """Remediation SLA in days per priority."""

    p1_days: int = Field(7, ge=1)
    p2_days: int = Field(30, ge=1)
    p3_days: int = Field(90, ge=1)
    p4_days: int = Field(180, ge=1)

    def days_for(self, priority: str | None) -> int:
        return {"P1": self.p1_days, "P2": self.p2_days, "P3": self.p3_days}.get(
            priority or "", self.p4_days
        )


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CR360_",
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    app_name: str = "CyberRemediate 360"
    app_env: Literal["demo", "production"] = "demo"
    database_url: str = f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"
    api_key: SecretStr | None = None
    cors_origins: list[str] = ["http://localhost:8501", "http://127.0.0.1:8501"]
    max_upload_bytes: int = Field(5 * 1024 * 1024, ge=1024)
    max_import_rows: int = Field(50_000, ge=1)
    scoring: ScoringConfig = ScoringConfig()
    sla: SlaConfig = SlaConfig()

    @property
    def write_auth_enabled(self) -> bool:
        return self.api_key is not None and bool(self.api_key.get_secret_value())


@lru_cache
def get_settings() -> Settings:
    return Settings()
