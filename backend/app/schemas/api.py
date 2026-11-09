"""Pydantic v2 request / response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.domain import (
    Criticality,
    Environment,
    Exposure,
    VerificationStatus,
    WorkflowStatus,
    cvss_severity,
)
from app.services.validation import ASSET_KEY_RE, HOSTNAME_RE

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ------------------------------------------------------------------------------ assets
class AssetCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    asset_key: str = Field(min_length=1, max_length=64, examples=["AST-100"])
    hostname: str = Field(min_length=1, max_length=253, examples=["web-01.example.test"])
    ip_address: str = Field(examples=["192.0.2.10"])
    owner: str | None = Field(default=None, max_length=120)
    environment: Environment = Environment.UNKNOWN
    business_criticality: Criticality = Criticality.UNKNOWN
    exposure: Exposure = Exposure.UNKNOWN
    is_demo: bool = False

    @field_validator("asset_key")
    @classmethod
    def _key(cls, v: str) -> str:
        if not ASSET_KEY_RE.fullmatch(v):
            raise ValueError("asset_key must be letters, digits, . _ : - (max 64)")
        return v.upper()

    @field_validator("hostname")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.lower().rstrip(".")
        if not HOSTNAME_RE.fullmatch(v):
            raise ValueError("invalid hostname")
        return v

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v: str) -> str:
        import ipaddress

        return str(ipaddress.ip_address(v))


class AssetUpdate(BaseModel):
    """Inventory context editable after creation (identity fields come from imports)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    owner: str | None = Field(default=None, max_length=120)
    environment: Environment | None = None
    business_criticality: Criticality | None = None
    exposure: Exposure | None = None


class AssetOut(ORM):
    id: int
    asset_key: str
    hostname: str
    ip_address: str
    owner: str | None
    environment: str
    business_criticality: str
    exposure: str
    is_demo: bool
    created_at: datetime
    updated_at: datetime


class AssetDetail(AssetOut):
    open_findings: int = 0
    findings: list[FindingOut] = []


# ---------------------------------------------------------------------- vulnerabilities
class VulnerabilityOut(ORM):
    id: int
    cve_id: str
    title: str | None
    description: str | None
    cwe_id: str | None
    cvss_version: str | None
    cvss_score: float | None
    cvss_vector: str | None
    references: list[str] | None
    epss_score: float | None
    kev: bool | None
    threat_source: str | None
    is_demo: bool

    @property
    def severity(self) -> str:
        return cvss_severity(self.cvss_score)


# ------------------------------------------------------------------------- remediation
class RemediationCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    finding_id: int = Field(gt=0)
    owner: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=3, max_length=4000)
    proposed_solution: str | None = Field(default=None, max_length=4000)
    notes: str | None = Field(default=None, max_length=4000)
    due_date: datetime | None = None
    status: WorkflowStatus = WorkflowStatus.OPEN


class RemediationUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    owner: str | None = Field(default=None, min_length=1, max_length=120)
    action: str | None = Field(default=None, min_length=3, max_length=4000)
    proposed_solution: str | None = Field(default=None, max_length=4000)
    notes: str | None = Field(default=None, max_length=4000)
    due_date: datetime | None = None
    status: WorkflowStatus | None = None
    verification_status: VerificationStatus | None = None
    evidence: str | None = Field(default=None, max_length=4000)
    justification: str | None = Field(default=None, min_length=5, max_length=4000)
    risk_acceptance_expires_at: datetime | None = None


class RemediationOut(ORM):
    id: int
    finding_id: int
    owner: str
    action: str
    proposed_solution: str | None
    notes: str | None
    status: str
    due_date: datetime | None
    completed_at: datetime | None
    verification_status: str
    evidence: str | None
    justification: str | None
    risk_acceptance_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime
    overdue: bool = False


# ------------------------------------------------------------------------------ findings
class FindingOut(ORM):
    id: int
    asset_id: int
    vulnerability_id: int
    asset_key: str | None = None
    hostname: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    scanner_source: str | None
    service: str | None
    port: int | None
    protocol: str | None
    location_key: str
    first_seen: datetime | None
    last_seen: datetime | None
    status: str
    risk_score: float | None
    priority: str | None
    evidence: str | None
    is_demo: bool


class FindingDetail(FindingOut):
    risk_explanation: dict[str, Any] | None
    asset: AssetOut
    vulnerability: VulnerabilityOut
    remediation: RemediationOut | None


# ------------------------------------------------------------------------------ imports
class ImportJobOut(ORM):
    id: int
    source: str
    filename: str
    file_sha256: str | None
    mode: str
    status: str
    total_rows: int
    imported: int
    updated: int
    rejected: int
    duplicates: int
    errors: list[dict] | None
    warnings: list[str] | None
    timestamp: datetime
    actor: str


# --------------------------------------------------------------------------------- audit
class AuditEventOut(ORM):
    id: int
    entity_type: str
    entity_id: str
    action: str
    previous_value: dict | None
    new_value: dict | None
    timestamp: datetime
    actor: str


class Health(BaseModel):
    status: str
    app: str
    version: str
    environment: str
    database: str
    write_auth: str
    time: datetime


AssetDetail.model_rebuild()
