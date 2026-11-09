"""Read-side data access: filtering, search, sorting and pagination via the ORM.

All user input reaches SQL only as bound parameters (SQLAlchemy expressions); sort
fields are mapped through explicit allow-lists, never interpolated.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.errors import DomainError
from app.models import Asset, AuditEvent, Finding, ImportJob, Remediation, Vulnerability


@dataclass
class PageParams:
    page: int = 1
    page_size: int = 50
    sort: str | None = None

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _apply_sort(query: Select, sort: str | None, allowed: dict, default) -> Select:
    if not sort:
        return query.order_by(*default)
    desc = sort.startswith("-")
    key = sort.lstrip("-+")
    if key not in allowed:
        raise DomainError(f"Unsupported sort field '{key}'", {"allowed": sorted(allowed)})
    column = allowed[key]
    return query.order_by(column.desc().nulls_last() if desc else column.asc().nulls_last())


def paginate(db: Session, query: Select, params: PageParams) -> tuple[list, int]:
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    items = list(db.scalars(query.offset(params.offset).limit(params.page_size)))
    return items, total


# ------------------------------------------------------------------------------ assets
ASSET_SORT = {
    "id": Asset.id,
    "asset_key": Asset.asset_key,
    "hostname": Asset.hostname,
    "business_criticality": Asset.business_criticality,
    "exposure": Asset.exposure,
    "created_at": Asset.created_at,
}


def list_assets(
    db: Session,
    params: PageParams,
    *,
    q=None,
    exposure=None,
    criticality=None,
    environment=None,
    is_demo=None,
):
    query = select(Asset)
    if q:
        like = _like(q)
        query = query.where(
            or_(
                Asset.hostname.ilike(like, escape="\\"),
                Asset.asset_key.ilike(like, escape="\\"),
                Asset.ip_address.ilike(like, escape="\\"),
                Asset.owner.ilike(like, escape="\\"),
            )
        )
    if exposure:
        query = query.where(Asset.exposure == exposure)
    if criticality:
        query = query.where(Asset.business_criticality == criticality)
    if environment:
        query = query.where(Asset.environment == environment)
    if is_demo is not None:
        query = query.where(Asset.is_demo.is_(is_demo))
    query = _apply_sort(query, params.sort, ASSET_SORT, [Asset.id])
    return paginate(db, query, params)


# ----------------------------------------------------------------------- vulnerabilities
VULN_SORT = {
    "id": Vulnerability.id,
    "cve_id": Vulnerability.cve_id,
    "cvss_score": Vulnerability.cvss_score,
    "epss_score": Vulnerability.epss_score,
}


def list_vulnerabilities(
    db: Session, params: PageParams, *, q=None, min_cvss=None, kev=None, is_demo=None
):
    query = select(Vulnerability)
    if q:
        like = _like(q)
        query = query.where(
            or_(
                Vulnerability.cve_id.ilike(like, escape="\\"),
                Vulnerability.title.ilike(like, escape="\\"),
                Vulnerability.cwe_id.ilike(like, escape="\\"),
            )
        )
    if min_cvss is not None:
        query = query.where(Vulnerability.cvss_score >= min_cvss)
    if kev is not None:
        query = query.where(Vulnerability.kev.is_(kev))
    if is_demo is not None:
        query = query.where(Vulnerability.is_demo.is_(is_demo))
    query = _apply_sort(
        query, params.sort, VULN_SORT, [Vulnerability.cvss_score.desc().nulls_last()]
    )
    return paginate(db, query, params)


# ------------------------------------------------------------------------------ findings
FINDING_SORT = {
    "id": Finding.id,
    "risk_score": Finding.risk_score,
    "priority": Finding.priority,
    "status": Finding.status,
    "first_seen": Finding.first_seen,
    "last_seen": Finding.last_seen,
    "cvss_score": Vulnerability.cvss_score,
    "hostname": Asset.hostname,
}


def list_findings(
    db: Session,
    params: PageParams,
    *,
    q=None,
    status=None,
    priority=None,
    asset_id=None,
    min_risk=None,
    min_cvss=None,
    exposure=None,
    is_demo=None,
):
    query = (
        select(Finding)
        .join(Finding.asset)
        .join(Finding.vulnerability)
        .options(selectinload(Finding.asset), selectinload(Finding.vulnerability))
    )
    if q:
        like = _like(q)
        query = query.where(
            or_(
                Vulnerability.cve_id.ilike(like, escape="\\"),
                Vulnerability.title.ilike(like, escape="\\"),
                Asset.hostname.ilike(like, escape="\\"),
                Asset.asset_key.ilike(like, escape="\\"),
                Finding.service.ilike(like, escape="\\"),
            )
        )
    if status:
        query = query.where(Finding.status.in_(status))
    if priority:
        query = query.where(Finding.priority.in_(priority))
    if asset_id is not None:
        query = query.where(Finding.asset_id == asset_id)
    if min_risk is not None:
        query = query.where(Finding.risk_score >= min_risk)
    if min_cvss is not None:
        query = query.where(Vulnerability.cvss_score >= min_cvss)
    if exposure:
        query = query.where(Asset.exposure == exposure)
    if is_demo is not None:
        query = query.where(Finding.is_demo.is_(is_demo))
    query = _apply_sort(
        query, params.sort, FINDING_SORT, [Finding.risk_score.desc().nulls_last(), Finding.id]
    )
    return paginate(db, query, params)


# -------------------------------------------------------------------------- remediations
REM_SORT = {
    "id": Remediation.id,
    "due_date": Remediation.due_date,
    "status": Remediation.status,
    "owner": Remediation.owner,
    "updated_at": Remediation.updated_at,
}


def list_remediations(
    db: Session, params: PageParams, *, status=None, owner=None, overdue_before=None
):
    query = select(Remediation)
    if status:
        query = query.where(Remediation.status.in_(status))
    if owner:
        query = query.where(Remediation.owner.ilike(_like(owner), escape="\\"))
    if overdue_before is not None:
        query = query.where(
            Remediation.due_date < overdue_before,
            Remediation.status.in_(["open", "in_progress", "mitigated"]),
        )
    query = _apply_sort(query, params.sort, REM_SORT, [Remediation.due_date.asc().nulls_last()])
    return paginate(db, query, params)


# -------------------------------------------------------------------------------- audit
def list_audit_events(
    db: Session, params: PageParams, *, entity_type=None, entity_id=None, action=None, actor=None
):
    query = select(AuditEvent)
    if entity_type:
        query = query.where(AuditEvent.entity_type == entity_type)
    if entity_id:
        query = query.where(AuditEvent.entity_id == entity_id)
    if action:
        query = query.where(AuditEvent.action == action)
    if actor:
        query = query.where(AuditEvent.actor == actor)
    query = query.order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc())
    return paginate(db, query, params)


def list_import_jobs(db: Session, params: PageParams):
    query = select(ImportJob).order_by(ImportJob.timestamp.desc(), ImportJob.id.desc())
    return paginate(db, query, params)
