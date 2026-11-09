"""Remediation workflow (one plan per finding) with enforced transitions.

State machine (docs/risk_scoring.md#workflow and docs/data_model.md):

    open ──► in_progress ──► mitigated ──► resolved
      │           │              │
      └───────────┴──────────────┴──► accepted | false_positive
    resolved / accepted / false_positive ──► open   (re-open, justification required)

Rules:
* resolved        -> evidence of the fix is required; verification becomes ``pending``
                     unless explicitly ``verified``; ``completed_at`` is set.
* mitigated       -> a justification describing the compensating control is required;
                     the finding stays active (root cause still present, SLA keeps running).
* accepted        -> justification + risk-acceptance expiry date (max 365 days) required.
* false_positive  -> justification required.
* re-open         -> justification required; ``completed_at`` cleared.
* ``verified`` verification status requires evidence and a resolved/mitigated status.
The finding status is always synchronised with its remediation status.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.domain import CLOSED_STATUSES, VerificationStatus, WorkflowStatus
from app.core.errors import ConflictError, InvalidTransitionError, NotFoundError
from app.core.timeutils import ensure_utc, utcnow
from app.models import Finding, Remediation
from app.services import audit

S = WorkflowStatus
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    S.OPEN: {S.IN_PROGRESS, S.MITIGATED, S.RESOLVED, S.ACCEPTED, S.FALSE_POSITIVE},
    S.IN_PROGRESS: {S.OPEN, S.MITIGATED, S.RESOLVED, S.ACCEPTED, S.FALSE_POSITIVE},
    S.MITIGATED: {S.IN_PROGRESS, S.RESOLVED, S.ACCEPTED, S.OPEN},
    S.RESOLVED: {S.OPEN},
    S.ACCEPTED: {S.OPEN, S.IN_PROGRESS},
    S.FALSE_POSITIVE: {S.OPEN},
}
MAX_ACCEPTANCE_DAYS = 365
TRACKED_FIELDS = [
    "owner",
    "action",
    "proposed_solution",
    "notes",
    "status",
    "due_date",
    "completed_at",
    "verification_status",
    "evidence",
    "justification",
    "risk_acceptance_expires_at",
]


def default_due_date(finding: Finding, settings: Settings) -> datetime:
    """SLA clock starts at first detection (or now if unknown)."""
    start = finding.first_seen or utcnow()
    return start + timedelta(days=settings.sla.days_for(finding.priority))


def _snapshot(rem: Remediation) -> dict:
    return {name: getattr(rem, name) for name in TRACKED_FIELDS}


def create_remediation(
    db: Session, data: dict, *, actor: str, settings: Settings | None = None
) -> Remediation:
    settings = settings or get_settings()
    finding = db.get(Finding, data["finding_id"])
    if finding is None:
        raise NotFoundError(f"Finding {data['finding_id']} not found")
    if db.scalar(select(Remediation.id).where(Remediation.finding_id == finding.id)):
        raise ConflictError("A remediation plan already exists for this finding; use PATCH")
    status = data.get("status") or S.OPEN
    if status not in (S.OPEN, S.IN_PROGRESS):
        raise InvalidTransitionError("A remediation can only be created as open or in_progress")
    due = ensure_utc(data.get("due_date")) or default_due_date(finding, settings)
    rem = Remediation(
        finding_id=finding.id,
        owner=data["owner"],
        action=data["action"],
        proposed_solution=data.get("proposed_solution"),
        notes=data.get("notes"),
        status=str(status),
        due_date=due,
        verification_status=VerificationStatus.NOT_VERIFIED.value,
    )
    db.add(rem)
    previous_status = finding.status
    finding.status = rem.status
    db.flush()
    audit.record_event(
        db,
        entity_type="remediation",
        entity_id=rem.id,
        action="remediation_created",
        actor=actor,
        new=_snapshot(rem),
    )
    if previous_status != finding.status:
        audit.record_event(
            db,
            entity_type="finding",
            entity_id=finding.id,
            action="status_changed",
            actor=actor,
            previous={"status": previous_status},
            new={"status": finding.status},
        )
    db.commit()
    db.refresh(rem)
    return rem


def _apply_transition(rem: Remediation, new_status: str, changes: dict) -> None:
    current = rem.status
    if new_status not in ALLOWED_TRANSITIONS[current]:
        raise InvalidTransitionError(
            f"Transition {current} -> {new_status} is not allowed",
            {"allowed": sorted(ALLOWED_TRANSITIONS[current])},
        )
    justification = changes.get("justification")
    evidence = changes.get("evidence") or rem.evidence
    now = utcnow()

    if current in CLOSED_STATUSES and new_status not in CLOSED_STATUSES and not justification:
        raise InvalidTransitionError("Re-opening a closed finding requires a justification")
    if new_status == S.RESOLVED:
        if not evidence:
            raise InvalidTransitionError("Resolving requires evidence of the fix")
        changes["completed_at"] = now
        if changes.get("verification_status") != VerificationStatus.VERIFIED:
            changes["verification_status"] = VerificationStatus.PENDING.value
    elif new_status == S.MITIGATED:
        if not justification:
            raise InvalidTransitionError(
                "Mitigation requires a justification describing the compensating control"
            )
        changes["completed_at"] = None
    elif new_status == S.ACCEPTED:
        expiry = (
            ensure_utc(changes.get("risk_acceptance_expires_at")) or rem.risk_acceptance_expires_at
        )
        if not justification:
            raise InvalidTransitionError("Risk acceptance requires a justification")
        if expiry is None or expiry <= now or expiry > now + timedelta(days=MAX_ACCEPTANCE_DAYS):
            raise InvalidTransitionError(
                f"Risk acceptance requires an expiry date within {MAX_ACCEPTANCE_DAYS} days"
            )
        changes["risk_acceptance_expires_at"] = expiry
        changes["completed_at"] = now
    elif new_status == S.FALSE_POSITIVE:
        if not justification:
            raise InvalidTransitionError("Marking a false positive requires a justification")
        changes["completed_at"] = now
    else:  # open / in_progress
        changes["completed_at"] = None
        if current in CLOSED_STATUSES:
            changes["verification_status"] = (
                VerificationStatus.FAILED.value
                if current == S.RESOLVED
                else VerificationStatus.NOT_VERIFIED.value
            )
            changes["risk_acceptance_expires_at"] = None


def update_remediation(db: Session, remediation_id: int, data: dict, *, actor: str) -> Remediation:
    rem = db.get(Remediation, remediation_id)
    if rem is None:
        raise NotFoundError(f"Remediation {remediation_id} not found")
    changes = {k: v for k, v in data.items() if k in TRACKED_FIELDS}
    for key in ("due_date", "risk_acceptance_expires_at"):
        if changes.get(key) is not None:
            changes[key] = ensure_utc(changes[key])
    for key in ("status", "verification_status"):
        if changes.get(key) is not None:
            changes[key] = str(getattr(changes[key], "value", changes[key]))
    changes.pop("completed_at", None)  # set by the workflow only

    new_status = changes.get("status")
    if new_status and new_status != rem.status:
        _apply_transition(rem, new_status, changes)
    else:
        changes.pop("status", None)

    target_status = changes.get("status", rem.status)
    verification = changes.get("verification_status")
    if verification == VerificationStatus.VERIFIED:
        if target_status not in (S.RESOLVED, S.MITIGATED):
            raise InvalidTransitionError("Only resolved or mitigated items can be verified")
        if not (changes.get("evidence") or rem.evidence):
            raise InvalidTransitionError("Verification requires evidence")

    previous, changed = audit.diff(rem, TRACKED_FIELDS, changes)
    if not changed:
        return rem
    for key, value in changed.items():
        setattr(rem, key, value)
    finding = rem.finding
    if "status" in changed and finding.status != rem.status:
        audit.record_event(
            db,
            entity_type="finding",
            entity_id=finding.id,
            action="status_changed",
            actor=actor,
            previous={"status": finding.status},
            new={"status": rem.status},
        )
        finding.status = rem.status
    action = "status_changed" if "status" in changed else "remediation_updated"
    audit.record_event(
        db,
        entity_type="remediation",
        entity_id=rem.id,
        action=action,
        actor=actor,
        previous=previous,
        new=changed,
    )
    db.commit()
    db.refresh(rem)
    return rem
