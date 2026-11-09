"""REST API v1 routes (mounted under /api/v1)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app import __version__
from app.core.config import get_settings
from app.core.database import get_db
from app.core.domain import ACTIVE_STATUSES, ImportMode, ImportSource, cvss_severity
from app.core.errors import ConflictError, NotFoundError
from app.core.security import get_actor, require_write_access
from app.core.timeutils import utcnow
from app.models import Asset, Finding, ImportJob, Remediation
from app.repositories import queries
from app.schemas.api import (
    AssetCreate,
    AssetDetail,
    AssetOut,
    AssetUpdate,
    AuditEventOut,
    FindingDetail,
    FindingOut,
    Health,
    ImportJobOut,
    Page,
    RemediationCreate,
    RemediationOut,
    RemediationUpdate,
    VulnerabilityOut,
)
from app.services import audit, dashboard, reporting
from app.services import remediation as remediation_service
from app.services.ingestion import run_import
from app.services.risk import rescore_findings

router = APIRouter(prefix="/api/v1")
DB = Annotated[Session, Depends(get_db)]
Actor = Annotated[str, Depends(get_actor)]
WRITE = [Depends(require_write_access)]


def page_params(
    page: int = Query(1, ge=1, le=100_000),
    page_size: int = Query(50, ge=1, le=500),
    sort: str | None = Query(None, max_length=40, description="Field name, prefix '-' for desc"),
) -> queries.PageParams:
    return queries.PageParams(page=page, page_size=page_size, sort=sort)


Paging = Annotated[queries.PageParams, Depends(page_params)]


def _page(items, total, params: queries.PageParams) -> dict:
    return {"items": items, "total": total, "page": params.page, "page_size": params.page_size}


def finding_out(f: Finding) -> FindingOut:
    out = FindingOut.model_validate(f)
    out.asset_key, out.hostname = f.asset.asset_key, f.asset.hostname
    out.cve_id, out.cvss_score = f.vulnerability.cve_id, f.vulnerability.cvss_score
    out.cvss_severity = cvss_severity(f.vulnerability.cvss_score)
    return out


def remediation_out(rem: Remediation) -> RemediationOut:
    out = RemediationOut.model_validate(rem)
    out.overdue = dashboard.is_overdue(rem, utcnow())
    return out


# ------------------------------------------------------------------------------ health
@router.get("/health", response_model=Health, tags=["system"])
def health(db: DB):
    settings = get_settings()
    try:
        db.execute(text("SELECT 1"))
        db_state = "ok"
    except Exception:  # noqa: BLE001
        db_state = "unavailable"
    return Health(
        status="ok" if db_state == "ok" else "degraded",
        app=settings.app_name,
        version=__version__,
        environment=settings.app_env,
        database=db_state,
        write_auth="api-key"
        if settings.write_auth_enabled
        else ("open-demo-mode" if settings.app_env == "demo" else "writes-disabled"),
        time=utcnow(),
    )


@router.get("/config/scoring", tags=["system"])
def scoring_config():
    settings = get_settings()
    return {
        "model": "cr360-additive-v1",
        "weights": settings.scoring.model_dump(),
        "sla_days": settings.sla.model_dump(),
    }


# ------------------------------------------------------------------------------ assets
@router.get("/assets", response_model=Page[AssetOut], tags=["assets"])
def list_assets(
    db: DB,
    params: Paging,
    q: str | None = Query(None, max_length=100),
    exposure: str | None = None,
    criticality: str | None = None,
    environment: str | None = None,
    is_demo: bool | None = None,
):
    items, total = queries.list_assets(
        db,
        params,
        q=q,
        exposure=exposure,
        criticality=criticality,
        environment=environment,
        is_demo=is_demo,
    )
    return _page(items, total, params)


@router.post(
    "/assets", response_model=AssetOut, status_code=201, tags=["assets"], dependencies=WRITE
)
def create_asset(payload: AssetCreate, db: DB, actor: Actor):
    if db.scalar(select(Asset.id).where(Asset.asset_key == payload.asset_key)):
        raise ConflictError(f"Asset '{payload.asset_key}' already exists")
    asset = Asset(**{k: getattr(v, "value", v) for k, v in payload.model_dump().items()})
    db.add(asset)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("Asset violates a database constraint") from exc
    audit.record_event(
        db,
        entity_type="asset",
        entity_id=asset.id,
        action="asset_created",
        actor=actor,
        new=payload.model_dump(mode="json"),
    )
    db.commit()
    return asset


@router.get("/assets/{asset_id}", response_model=AssetDetail, tags=["assets"])
def get_asset(asset_id: int, db: DB):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError(f"Asset {asset_id} not found")
    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.asset_id == asset_id)
            .options(selectinload(Finding.asset), selectinload(Finding.vulnerability))
            .order_by(Finding.risk_score.desc().nulls_last())
        )
    )
    detail = AssetDetail.model_validate(asset)
    detail.findings = [finding_out(f) for f in findings]
    detail.open_findings = sum(1 for f in findings if f.status in ACTIVE_STATUSES)
    return detail


@router.patch("/assets/{asset_id}", response_model=AssetOut, tags=["assets"], dependencies=WRITE)
def update_asset(asset_id: int, payload: AssetUpdate, db: DB, actor: Actor):
    """Update inventory context; findings of the asset are re-scored automatically."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError(f"Asset {asset_id} not found")
    values = {k: getattr(v, "value", v) for k, v in payload.model_dump(exclude_unset=True).items()}
    previous, changed = audit.diff(asset, list(values), values)
    if changed:
        for key, value in changed.items():
            setattr(asset, key, value)
        audit.record_event(
            db,
            entity_type="asset",
            entity_id=asset.id,
            action="asset_updated",
            actor=actor,
            previous=previous,
            new=changed,
        )
        db.flush()
        ids = db.scalars(select(Finding.id).where(Finding.asset_id == asset.id))
        rescore_findings(db, list(ids), actor=actor)
        db.commit()
    return asset


# ----------------------------------------------------------------------- vulnerabilities
@router.get("/vulnerabilities", response_model=Page[VulnerabilityOut], tags=["vulnerabilities"])
def list_vulnerabilities(
    db: DB,
    params: Paging,
    q: str | None = Query(None, max_length=100),
    min_cvss: float | None = Query(None, ge=0, le=10),
    kev: bool | None = None,
    is_demo: bool | None = None,
):
    items, total = queries.list_vulnerabilities(
        db, params, q=q, min_cvss=min_cvss, kev=kev, is_demo=is_demo
    )
    return _page(items, total, params)


# ------------------------------------------------------------------------------ findings
@router.get("/findings", response_model=Page[FindingOut], tags=["findings"])
def list_findings(
    db: DB,
    params: Paging,
    q: str | None = Query(None, max_length=100),
    status_: list[str] | None = Query(None, alias="status"),
    priority: list[str] | None = Query(None),
    asset_id: int | None = None,
    min_risk: float | None = Query(None, ge=0, le=100),
    min_cvss: float | None = Query(None, ge=0, le=10),
    exposure: str | None = None,
    is_demo: bool | None = None,
):
    items, total = queries.list_findings(
        db,
        params,
        q=q,
        status=status_,
        priority=priority,
        asset_id=asset_id,
        min_risk=min_risk,
        min_cvss=min_cvss,
        exposure=exposure,
        is_demo=is_demo,
    )
    return _page([finding_out(f) for f in items], total, params)


@router.get("/findings/{finding_id}", response_model=FindingDetail, tags=["findings"])
def get_finding(finding_id: int, db: DB):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError(f"Finding {finding_id} not found")
    base = finding_out(finding).model_dump()
    return FindingDetail(
        **base,
        risk_explanation=finding.risk_explanation,
        asset=AssetOut.model_validate(finding.asset),
        vulnerability=VulnerabilityOut.model_validate(finding.vulnerability),
        remediation=remediation_out(finding.remediation) if finding.remediation else None,
    )


# ------------------------------------------------------------------------------ imports
@router.post(
    "/imports", response_model=ImportJobOut, status_code=201, tags=["imports"], dependencies=WRITE
)
async def create_import(
    db: DB,
    actor: Actor,
    file: UploadFile = File(..., description="CSV or JSON file (max 5 MB by default)"),
    source: ImportSource = Form(ImportSource.NORMALIZED_CSV),
    mode: ImportMode = Form(
        ImportMode.PRODUCTION, description="'demo' additionally accepts fictional CVE-DEMO ids"
    ),
):
    limit = get_settings().max_upload_bytes
    content = await file.read(limit + 1)
    return run_import(
        db,
        content=content,
        filename=file.filename or "upload",
        source=source,
        mode=mode,
        actor=actor,
    )


@router.get("/imports", response_model=Page[ImportJobOut], tags=["imports"])
def list_imports(db: DB, params: Paging):
    items, total = queries.list_import_jobs(db, params)
    return _page(items, total, params)


@router.get("/imports/{job_id}", response_model=ImportJobOut, tags=["imports"])
def get_import(job_id: int, db: DB):
    job = db.get(ImportJob, job_id)
    if job is None:
        raise NotFoundError(f"Import job {job_id} not found")
    return job


# ----------------------------------------------------------------------------- dashboard
@router.get("/dashboard/summary", tags=["dashboard"])
def dashboard_summary(db: DB, include_demo: bool = True):
    return dashboard.summary(db, include_demo)


@router.get("/dashboard/trends", tags=["dashboard"])
def dashboard_trends(db: DB, include_demo: bool = True):
    return dashboard.trends(db, include_demo)


# -------------------------------------------------------------------------- remediations
@router.get("/remediations", response_model=Page[RemediationOut], tags=["remediations"])
def list_remediations(
    db: DB,
    params: Paging,
    status_: list[str] | None = Query(None, alias="status"),
    owner: str | None = Query(None, max_length=120),
    overdue: bool = False,
):
    items, total = queries.list_remediations(
        db, params, status=status_, owner=owner, overdue_before=utcnow() if overdue else None
    )
    return _page([remediation_out(r) for r in items], total, params)


@router.get("/remediations/{remediation_id}", response_model=RemediationOut, tags=["remediations"])
def get_remediation(remediation_id: int, db: DB):
    rem = db.get(Remediation, remediation_id)
    if rem is None:
        raise NotFoundError(f"Remediation {remediation_id} not found")
    return remediation_out(rem)


@router.post(
    "/remediations",
    response_model=RemediationOut,
    status_code=201,
    tags=["remediations"],
    dependencies=WRITE,
)
def create_remediation(payload: RemediationCreate, db: DB, actor: Actor):
    rem = remediation_service.create_remediation(db, payload.model_dump(), actor=actor)
    return remediation_out(rem)


@router.patch(
    "/remediations/{remediation_id}",
    response_model=RemediationOut,
    tags=["remediations"],
    dependencies=WRITE,
)
def update_remediation(remediation_id: int, payload: RemediationUpdate, db: DB, actor: Actor):
    rem = remediation_service.update_remediation(
        db, remediation_id, payload.model_dump(exclude_unset=True), actor=actor
    )
    return remediation_out(rem)


# --------------------------------------------------------------------------------- audit
@router.get("/audit-events", response_model=Page[AuditEventOut], tags=["audit"])
def list_audit_events(
    db: DB,
    params: Paging,
    entity_type: str | None = None,
    entity_id: str | None = None,
    action: str | None = None,
    actor: str | None = None,
):
    items, total = queries.list_audit_events(
        db, params, entity_type=entity_type, entity_id=entity_id, action=action, actor=actor
    )
    return _page(items, total, params)


# ------------------------------------------------------------------------------- reports
MEDIA = {"pdf": "application/pdf", "csv": "text/csv; charset=utf-8", "json": "application/json"}


@router.get(
    "/reports/export",
    tags=["reports"],
    responses={200: {"content": {v: {} for v in MEDIA.values()}}},
)
def export_report(
    db: DB,
    format: str = Query("pdf", pattern="^(pdf|csv|json)$"),  # noqa: A002
    include_demo: bool = True,
):
    data = reporting.build_report_data(db, include_demo)
    renderer = {
        "pdf": reporting.render_pdf,
        "csv": reporting.render_csv,
        "json": reporting.render_json,
    }[format]
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=renderer(data),
        media_type=MEDIA[format],
        headers={"Content-Disposition": f'attachment; filename="cr360-report-{stamp}.{format}"'},
    )
