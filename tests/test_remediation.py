from datetime import timedelta

import pytest
from conftest import make_csv
from sqlalchemy import select

from app.core.domain import ImportMode, ImportSource
from app.core.errors import ConflictError, InvalidTransitionError, NotFoundError
from app.core.timeutils import utcnow
from app.models import AuditEvent, Finding
from app.services.ingestion import run_import
from app.services.remediation import create_remediation, update_remediation


@pytest.fixture
def finding(db):
    run_import(
        db,
        content=make_csv("AST-1,web-1,192.0.2.1,CVE-2021-44228,10.0,internet,critical,open"),
        filename="s.csv",
        source=ImportSource.NORMALIZED_CSV,
        mode=ImportMode.PRODUCTION,
        actor="t",
    )
    return db.scalar(select(Finding))


@pytest.fixture
def rem(db, finding):
    return create_remediation(
        db, {"finding_id": finding.id, "owner": "Ops", "action": "Patch"}, actor="alice"
    )


def test_create_sets_sla_due_date(rem, finding):
    # P1 -> 7 days from first_seen
    assert rem.due_date == finding.first_seen + timedelta(days=7)
    assert rem.status == "open" and rem.verification_status == "not_verified"


def test_create_conflicts_and_missing_finding(db, rem, finding):
    with pytest.raises(ConflictError):
        create_remediation(db, {"finding_id": finding.id, "owner": "x", "action": "y"}, actor="t")
    with pytest.raises(NotFoundError):
        create_remediation(db, {"finding_id": 9999, "owner": "x", "action": "y"}, actor="t")
    with pytest.raises(InvalidTransitionError):
        other = make_csv("AST-2,web-2,192.0.2.2,CVE-2021-44228,10.0,internet,critical,open")
        run_import(
            db,
            content=other,
            filename="s.csv",
            source=ImportSource.NORMALIZED_CSV,
            mode=ImportMode.PRODUCTION,
            actor="t",
        )
        f2 = db.scalar(select(Finding).where(Finding.id != finding.id))
        create_remediation(
            db, {"finding_id": f2.id, "owner": "x", "action": "y", "status": "resolved"}, actor="t"
        )


def test_resolve_requires_evidence_and_sets_closure(db, rem):
    with pytest.raises(InvalidTransitionError):
        update_remediation(db, rem.id, {"status": "resolved"}, actor="t")
    rem = update_remediation(
        db, rem.id, {"status": "resolved", "evidence": "KB123 installed"}, actor="bob"
    )
    assert rem.completed_at is not None and rem.verification_status == "pending"
    assert rem.finding.status == "resolved"
    rem = update_remediation(db, rem.id, {"verification_status": "verified"}, actor="carol")
    assert rem.verification_status == "verified"


def test_reopen_requires_justification(db, rem):
    update_remediation(db, rem.id, {"status": "resolved", "evidence": "e"}, actor="t")
    with pytest.raises(InvalidTransitionError):
        update_remediation(db, rem.id, {"status": "open"}, actor="t")
    with pytest.raises(InvalidTransitionError):  # resolved -> mitigated not allowed
        update_remediation(db, rem.id, {"status": "mitigated", "justification": "xxxxx"}, actor="t")
    rem = update_remediation(
        db, rem.id, {"status": "open", "justification": "rescan failed"}, actor="t"
    )
    assert rem.completed_at is None and rem.verification_status == "failed"


def test_mitigation_accept_false_positive_rules(db, rem):
    with pytest.raises(InvalidTransitionError):
        update_remediation(db, rem.id, {"status": "mitigated"}, actor="t")
    rem = update_remediation(
        db, rem.id, {"status": "mitigated", "justification": "WAF rule"}, actor="t"
    )
    assert rem.completed_at is None
    with pytest.raises(InvalidTransitionError):  # missing expiry
        update_remediation(db, rem.id, {"status": "accepted", "justification": "biz"}, actor="t")
    with pytest.raises(InvalidTransitionError):  # expiry too far
        update_remediation(
            db,
            rem.id,
            {
                "status": "accepted",
                "justification": "biz",
                "risk_acceptance_expires_at": utcnow() + timedelta(days=400),
            },
            actor="t",
        )
    rem = update_remediation(
        db,
        rem.id,
        {
            "status": "accepted",
            "justification": "biz",
            "risk_acceptance_expires_at": utcnow() + timedelta(days=30),
        },
        actor="t",
    )
    assert rem.completed_at is not None and rem.finding.status == "accepted"


def test_false_positive_and_verification_guard(db, rem):
    with pytest.raises(InvalidTransitionError):
        update_remediation(db, rem.id, {"status": "false_positive"}, actor="t")
    with pytest.raises(InvalidTransitionError):
        update_remediation(db, rem.id, {"verification_status": "verified"}, actor="t")
    rem = update_remediation(
        db,
        rem.id,
        {"status": "false_positive", "justification": "service not installed"},
        actor="t",
    )
    assert rem.finding.status == "false_positive"


def test_audit_trail_records_changes(db, rem):
    update_remediation(db, rem.id, {"status": "in_progress", "owner": "SecOps"}, actor="dave")
    events = list(db.scalars(select(AuditEvent).where(AuditEvent.actor == "dave")))
    rem_event = next(e for e in events if e.entity_type == "remediation")
    assert rem_event.action == "status_changed"
    assert rem_event.previous_value == {"status": "open", "owner": "Ops"}
    assert rem_event.new_value == {"status": "in_progress", "owner": "SecOps"}
    assert any(e.entity_type == "finding" for e in events)
    # no-op update records nothing
    before = len(list(db.scalars(select(AuditEvent))))
    update_remediation(db, rem.id, {"owner": "SecOps"}, actor="dave")
    assert len(list(db.scalars(select(AuditEvent)))) == before
