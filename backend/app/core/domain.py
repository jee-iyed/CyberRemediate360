"""Controlled vocabularies shared by models, schemas, services and the UI."""

from __future__ import annotations

from enum import StrEnum


class Exposure(StrEnum):
    INTERNET = "internet"
    INTERNAL = "internal"
    ISOLATED = "isolated"
    UNKNOWN = "unknown"


class Criticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Environment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    UNKNOWN = "unknown"


class WorkflowStatus(StrEnum):
    """Lifecycle shared by findings and their remediation plan."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    MITIGATED = "mitigated"  # compensating control in place, root cause still present
    RESOLVED = "resolved"  # root cause fixed (patch / config change)
    ACCEPTED = "accepted"  # risk formally accepted by an owner, with justification
    FALSE_POSITIVE = "false_positive"  # finding proven not applicable


class VerificationStatus(StrEnum):
    NOT_VERIFIED = "not_verified"
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class ImportSource(StrEnum):
    NORMALIZED_CSV = "normalized_csv"
    NORMALIZED_JSON = "normalized_json"
    NESSUS_CSV = "nessus_csv"


class ImportMode(StrEnum):
    PRODUCTION = "production"  # only real CVE identifiers (CVE-YYYY-NNNN+)
    DEMO = "demo"  # additionally accepts fictional CVE-DEMO-NNN identifiers


# Statuses after which a finding no longer counts as an open risk.
CLOSED_STATUSES = {
    WorkflowStatus.RESOLVED,
    WorkflowStatus.ACCEPTED,
    WorkflowStatus.FALSE_POSITIVE,
}
# Statuses where the vulnerability still needs work (mitigated = reduced but not fixed).
ACTIVE_STATUSES = {WorkflowStatus.OPEN, WorkflowStatus.IN_PROGRESS, WorkflowStatus.MITIGATED}


def values(enum_cls: type[StrEnum]) -> list[str]:
    return [e.value for e in enum_cls]


def cvss_severity(score: float | None) -> str:
    """Qualitative severity rating scale of CVSS v3.x / v4.0 (FIRST)."""
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
