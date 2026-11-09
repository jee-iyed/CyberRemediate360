"""KPI and trend computations. Every number is derived from the database at call time."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.domain import ACTIVE_STATUSES, WorkflowStatus, cvss_severity
from app.core.timeutils import utcnow
from app.models import Asset, Finding, ImportJob, Remediation

ACTIVE = [s.value for s in ACTIVE_STATUSES]


def _load_findings(db: Session, include_demo: bool = True) -> list[Finding]:
    query = select(Finding).options(
        selectinload(Finding.asset),
        selectinload(Finding.vulnerability),
        selectinload(Finding.remediation),
    )
    if not include_demo:
        query = query.where(Finding.is_demo.is_(False))
    return list(db.scalars(query))


def is_overdue(rem: Remediation | None, now: datetime) -> bool:
    return bool(rem and rem.due_date and rem.status in ACTIVE and rem.due_date < now)


def summary(db: Session, include_demo: bool = True) -> dict:
    now = utcnow()
    findings = _load_findings(db, include_demo)
    active = [f for f in findings if f.status in ACTIVE]
    asset_query = select(func.count(Asset.id))
    if not include_demo:
        asset_query = asset_query.where(Asset.is_demo.is_(False))
    total_assets = db.scalar(asset_query) or 0

    by_status = Counter(f.status for f in findings)
    by_severity = Counter(cvss_severity(f.vulnerability.cvss_score) for f in active)
    by_priority = Counter(f.priority or "unscored" for f in active)
    overdue = [f for f in findings if is_overdue(f.remediation, now)]

    per_asset: dict[int, dict] = {}
    for f in active:
        entry = per_asset.setdefault(
            f.asset_id,
            {
                "asset_id": f.asset_id,
                "asset_key": f.asset.asset_key,
                "hostname": f.asset.hostname,
                "exposure": f.asset.exposure,
                "business_criticality": f.asset.business_criticality,
                "open_findings": 0,
                "max_risk_score": 0.0,
                "total_risk_score": 0.0,
            },
        )
        entry["open_findings"] += 1
        entry["max_risk_score"] = max(entry["max_risk_score"], f.risk_score or 0.0)
        entry["total_risk_score"] = round(entry["total_risk_score"] + (f.risk_score or 0.0), 1)
    top_assets = sorted(
        per_asset.values(), key=lambda e: (e["max_risk_score"], e["total_risk_score"]), reverse=True
    )[:10]

    durations = [
        (f.remediation.completed_at - f.first_seen).total_seconds() / 86400
        for f in findings
        if f.status == WorkflowStatus.RESOLVED
        and f.remediation
        and f.remediation.completed_at
        and f.first_seen
    ]
    incomplete = [
        f.id
        for f in findings
        if f.risk_explanation
        and {"cvss_score", "exposure", "business_criticality"}
        & set(f.risk_explanation.get("missing_inputs", []))
    ]
    with_rem = sum(1 for f in active if f.remediation is not None)
    return {
        "generated_at": now.isoformat(),
        "include_demo": include_demo,
        "total_assets": total_assets,
        "total_findings": len(findings),
        "open_findings": len(active),
        "high_critical_open": sum(1 for f in active if (f.vulnerability.cvss_score or 0) >= 7.0),
        "p1_open": by_priority.get("P1", 0),
        "overdue_remediations": len(overdue),
        "resolved_findings": by_status.get(WorkflowStatus.RESOLVED.value, 0),
        "accepted_findings": by_status.get(WorkflowStatus.ACCEPTED.value, 0),
        "false_positive_findings": by_status.get(WorkflowStatus.FALSE_POSITIVE.value, 0),
        "mitigated_findings": by_status.get(WorkflowStatus.MITIGATED.value, 0),
        "by_status": dict(by_status),
        "by_severity": dict(by_severity),
        "by_priority": dict(by_priority),
        "top_assets": top_assets,
        "remediation_coverage": {
            "active_with_plan": with_rem,
            "active_total": len(active),
            "ratio": round(with_rem / len(active), 3) if active else None,
        },
        "mean_time_to_resolve_days": {
            "value": round(sum(durations) / len(durations), 1) if durations else None,
            "sample_size": len(durations),
        },
        "data_quality": {
            "findings_with_incomplete_scoring_inputs": len(incomplete),
            "findings_without_first_seen": sum(1 for f in findings if f.first_seen is None),
            "demo_findings": sum(1 for f in findings if f.is_demo),
            "real_findings": sum(1 for f in findings if not f.is_demo),
        },
    }


def _week_start(value: datetime) -> str:
    return (value - timedelta(days=value.weekday())).date().isoformat()


def trends(db: Session, include_demo: bool = True) -> dict:
    """Weekly counts built only from dates actually recorded (no interpolation)."""
    findings = _load_findings(db, include_demo)
    weeks: dict[str, dict] = defaultdict(
        lambda: {"new_findings": 0, "closed_findings": 0, "imports": 0}
    )
    for f in findings:
        if f.first_seen:
            weeks[_week_start(f.first_seen)]["new_findings"] += 1
        rem = f.remediation
        if (
            rem
            and rem.completed_at
            and f.status
            in (WorkflowStatus.RESOLVED, WorkflowStatus.ACCEPTED, WorkflowStatus.FALSE_POSITIVE)
        ):
            weeks[_week_start(rem.completed_at)]["closed_findings"] += 1
    for job in db.scalars(select(ImportJob).where(ImportJob.status == "completed")):
        weeks[_week_start(job.timestamp)]["imports"] += 1
    series = [{"week_start": k, **v} for k, v in sorted(weeks.items())]
    return {
        "granularity": "week",
        "series": series,
        "excluded": {
            "findings_without_first_seen": sum(1 for f in findings if f.first_seen is None)
        },
        "note": "Counts use recorded first_seen / completed_at / import timestamps only.",
    }
