"""SQLAlchemy 2.x ORM models.

Business keys (documented in docs/data_model.md):

* Asset         -> ``asset_key`` (inventory identifier such as ``AST-001``)
* Vulnerability -> ``cve_id``
* Finding       -> (``asset_id``, ``vulnerability_id``, ``location_key``) where
  ``location_key`` is ``"<protocol>/<port>"`` when the scanner reports a port, else ``""``.
  The same CVE on two ports of the same host is therefore two findings, while the same
  CVE re-reported on the same port is an UPSERT of the existing finding.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, UTCDateTime
from app.core.domain import (
    Criticality,
    Exposure,
    VerificationStatus,
    WorkflowStatus,
    values,
)
from app.core.timeutils import utcnow


def _in(column: str, enum_cls) -> str:
    allowed = ", ".join(f"'{v}'" for v in values(enum_cls))
    return f"{column} IN ({allowed})"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    owner: Mapped[str | None] = mapped_column(String(120))
    environment: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    business_criticality: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Criticality.UNKNOWN.value
    )
    exposure: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Exposure.UNKNOWN.value
    )
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    findings: Mapped[list[Finding]] = relationship(back_populates="asset")

    __table_args__ = (
        CheckConstraint(_in("business_criticality", Criticality), name="ck_assets_criticality"),
        CheckConstraint(_in("exposure", Exposure), name="ck_assets_exposure"),
    )


class Vulnerability(TimestampMixin, Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    title: Mapped[str | None] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text)
    cwe_id: Mapped[str | None] = mapped_column(String(16))
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    references: Mapped[list | None] = mapped_column("reference_links", JSON)
    # Threat signals: only stored when supplied by a documented source (never guessed).
    epss_score: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool | None] = mapped_column(Boolean)
    threat_source: Mapped[str | None] = mapped_column(String(120))
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    findings: Mapped[list[Finding]] = relationship(back_populates="vulnerability")

    __table_args__ = (
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="ck_vuln_cvss_range",
        ),
        CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)",
            name="ck_vuln_epss_range",
        ),
    )


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    scanner_source: Mapped[str | None] = mapped_column(String(64))
    service: Mapped[str | None] = mapped_column(String(64))
    port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(8))
    location_key: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=WorkflowStatus.OPEN.value
    )
    risk_score: Mapped[float | None] = mapped_column(Float)
    priority: Mapped[str | None] = mapped_column(String(4))
    risk_explanation: Mapped[dict | None] = mapped_column(JSON)
    evidence: Mapped[str | None] = mapped_column(Text)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    asset: Mapped[Asset] = relationship(back_populates="findings")
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="findings")
    remediation: Mapped[Remediation | None] = relationship(back_populates="finding", uselist=False)

    __table_args__ = (
        UniqueConstraint(
            "asset_id", "vulnerability_id", "location_key", name="uq_findings_business_key"
        ),
        CheckConstraint(_in("status", WorkflowStatus), name="ck_findings_status"),
        CheckConstraint("port IS NULL OR (port >= 0 AND port <= 65535)", name="ck_findings_port"),
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
            name="ck_findings_risk_range",
        ),
        Index("ix_findings_status_priority", "status", "priority"),
        Index("ix_findings_risk_score", "risk_score"),
    )


class Remediation(TimestampMixin, Base):
    """One remediation plan per finding; its history lives in the audit trail."""

    __tablename__ = "remediations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="RESTRICT"), nullable=False, unique=True
    )
    owner: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_solution: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=WorkflowStatus.OPEN.value
    )
    due_date: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    verification_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=VerificationStatus.NOT_VERIFIED.value
    )
    evidence: Mapped[str | None] = mapped_column(Text)
    justification: Mapped[str | None] = mapped_column(Text)
    risk_acceptance_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    finding: Mapped[Finding] = relationship(back_populates="remediation")

    __table_args__ = (
        CheckConstraint(_in("status", WorkflowStatus), name="ck_remediations_status"),
        CheckConstraint(
            _in("verification_status", VerificationStatus), name="ck_remediations_verification"
        ),
        Index("ix_remediations_status", "status"),
    )


class AuditEvent(Base):
    """Append-only journal of significant changes (no update/delete endpoint exists)."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    previous_value: Mapped[dict | None] = mapped_column(JSON)
    new_value: Mapped[dict | None] = mapped_column(JSON)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_audit_entity", "entity_type", "entity_id"),
        Index("ix_audit_timestamp", "timestamp"),
    )


class ImportJob(Base):
    __tablename__ = "import_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_sha256: Mapped[str | None] = mapped_column(String(64))
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # completed | failed
    total_rows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    imported: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rejected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors: Mapped[list | None] = mapped_column(JSON)
    warnings: Mapped[list | None] = mapped_column(JSON)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
