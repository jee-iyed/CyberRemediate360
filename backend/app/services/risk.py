"""Applies the scoring model to stored findings."""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings, get_settings
from app.models import Finding
from app.services import audit
from app.services.scoring import RiskInput, compute_risk


def score_finding(finding: Finding, settings: Settings | None = None):
    settings = settings or get_settings()
    vuln, asset = finding.vulnerability, finding.asset
    return compute_risk(
        RiskInput(
            cvss_score=vuln.cvss_score,
            exposure=asset.exposure,
            business_criticality=asset.business_criticality,
            kev=vuln.kev,
            epss_score=vuln.epss_score,
        ),
        settings.scoring,
    )


def rescore_findings(
    db: Session,
    finding_ids: Iterable[int] | None,
    *,
    actor: str,
    settings: Settings | None = None,
) -> int:
    """Recompute score/priority. ``None`` means all findings. Returns the count updated."""
    query = select(Finding).options(
        selectinload(Finding.asset), selectinload(Finding.vulnerability)
    )
    if finding_ids is not None:
        ids = list(finding_ids)
        if not ids:
            return 0
        query = query.where(Finding.id.in_(ids))
    count = 0
    for finding in db.scalars(query):
        result = score_finding(finding, settings)
        if finding.priority is not None and finding.priority != result.priority:
            audit.record_event(
                db,
                entity_type="finding",
                entity_id=finding.id,
                action="priority_changed",
                actor=actor,
                previous={"risk_score": finding.risk_score, "priority": finding.priority},
                new={"risk_score": result.score, "priority": result.priority},
            )
        finding.risk_score = result.score
        finding.priority = result.priority
        finding.risk_explanation = result.to_dict()
        count += 1
    db.flush()
    return count
