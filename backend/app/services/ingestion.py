"""Import pipeline: decode -> parse -> validate -> de-duplicate -> UPSERT -> score -> audit.

UPSERT strategy (docs/data_model.md):

* Asset by ``asset_key``: created if absent; otherwise only the fields explicitly present
  in the row are updated (a scanner row never wipes inventory context such as owner).
* Vulnerability by ``cve_id``: created if absent; provided metadata updates the record.
* Finding by (asset, vulnerability, location_key): created if absent (``first_seen``),
  otherwise ``last_seen`` is advanced. The workflow status is NOT taken from the scanner
  for existing findings, except a regression rule: a finding marked ``resolved`` that is
  observed again after its closure is re-opened and its verification set to ``failed``.
* A finding absent from a new scan is NEVER closed automatically.

Atomicity: all valid rows of a file are written in a single transaction; on database
error everything is rolled back and the job is recorded as ``failed``.
Idempotency: importing the same file twice creates no new rows (second run = updates).
"""

from __future__ import annotations

import hashlib
import logging

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.domain import ImportMode, ImportSource, VerificationStatus, WorkflowStatus
from app.core.errors import ImportRejectedError, PayloadTooLargeError
from app.core.timeutils import utcnow
from app.models import Asset, Finding, ImportJob, Vulnerability
from app.services import audit
from app.services.parsers import PARSERS, check_extension, decode, safe_filename
from app.services.risk import rescore_findings
from app.services.validation import FindingRecord, validate_row

log = logging.getLogger(__name__)

ASSET_FIELDS = [
    "hostname",
    "ip_address",
    "owner",
    "environment",
    "business_criticality",
    "exposure",
]
VULN_FIELDS = [
    "title",
    "description",
    "cwe_id",
    "cvss_version",
    "cvss_score",
    "cvss_vector",
    "references",
    "epss_score",
    "kev",
    "threat_source",
]
MAX_ERRORS_STORED = 500


def _enum_value(value):
    return getattr(value, "value", value)


def _record_fields(record: FindingRecord, fields: list[str]) -> dict:
    """Only fields explicitly provided (non-null) in the input row."""
    data = {}
    for name in fields:
        value = getattr(record, name)
        if value is not None:
            data[name] = _enum_value(value)
    return data


def _upsert_asset(
    db: Session, rec: FindingRecord, is_demo: bool, actor: str, cache: dict
) -> tuple[Asset, bool]:
    asset = cache.get(rec.asset_id)
    if asset is None:
        asset = db.scalar(select(Asset).where(Asset.asset_key == rec.asset_id))
    provided = _record_fields(rec, ASSET_FIELDS)
    changed_context = False
    if asset is None:
        asset = Asset(asset_key=rec.asset_id, is_demo=is_demo, **provided)
        asset.environment = provided.get("environment", "unknown")
        asset.exposure = provided.get("exposure", "unknown")
        asset.business_criticality = provided.get("business_criticality", "unknown")
        db.add(asset)
        db.flush()
        audit.record_event(
            db,
            entity_type="asset",
            entity_id=asset.id,
            action="asset_created",
            actor=actor,
            new={"asset_key": asset.asset_key, **provided},
        )
    else:
        previous, changed = audit.diff(asset, ASSET_FIELDS, provided)
        if changed:
            for key, value in changed.items():
                setattr(asset, key, value)
            audit.record_event(
                db,
                entity_type="asset",
                entity_id=asset.id,
                action="asset_updated_by_import",
                actor=actor,
                previous=previous,
                new=changed,
            )
            changed_context = bool({"exposure", "business_criticality"} & changed.keys())
    cache[rec.asset_id] = asset
    return asset, changed_context


def _upsert_vulnerability(
    db: Session, rec: FindingRecord, is_demo: bool, actor: str, cache: dict
) -> tuple[Vulnerability, bool]:
    vuln = cache.get(rec.cve_id)
    if vuln is None:
        vuln = db.scalar(select(Vulnerability).where(Vulnerability.cve_id == rec.cve_id))
    provided = _record_fields(rec, VULN_FIELDS)
    changed_scoring = False
    if vuln is None:
        vuln = Vulnerability(
            cve_id=rec.cve_id, is_demo=is_demo or rec.cve_id.startswith("CVE-DEMO-"), **provided
        )
        db.add(vuln)
        db.flush()
    else:
        previous, changed = audit.diff(vuln, VULN_FIELDS, provided)
        if changed:
            for key, value in changed.items():
                setattr(vuln, key, value)
            audit.record_event(
                db,
                entity_type="vulnerability",
                entity_id=vuln.id,
                action="vulnerability_updated_by_import",
                actor=actor,
                previous=previous,
                new=changed,
            )
            changed_scoring = bool({"cvss_score", "kev", "epss_score"} & changed.keys())
    cache[rec.cve_id] = vuln
    return vuln, changed_scoring


def _upsert_finding(
    db: Session,
    rec: FindingRecord,
    asset: Asset,
    vuln: Vulnerability,
    is_demo: bool,
    source: str,
    observed_at,
    actor: str,
) -> tuple[Finding, bool]:
    finding = db.scalar(
        select(Finding).where(
            Finding.asset_id == asset.id,
            Finding.vulnerability_id == vuln.id,
            Finding.location_key == rec.location_key,
        )
    )
    seen_last = rec.last_seen or rec.first_seen or observed_at
    seen_first = rec.first_seen or seen_last
    if finding is None:
        finding = Finding(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            scanner_source=rec.scanner_source or source,
            service=rec.service,
            port=rec.port,
            protocol=rec.protocol,
            location_key=rec.location_key,
            first_seen=seen_first,
            last_seen=seen_last,
            status=rec.status or WorkflowStatus.OPEN.value,
            evidence=rec.evidence,
            is_demo=is_demo,
        )
        db.add(finding)
        db.flush()
        return finding, True

    finding.first_seen = min(finding.first_seen, seen_first) if finding.first_seen else seen_first
    finding.last_seen = max(finding.last_seen, seen_last) if finding.last_seen else seen_last
    if rec.evidence:
        finding.evidence = rec.evidence
    if rec.service and not finding.service:
        finding.service = rec.service

    remediation = finding.remediation
    closed_at = remediation.completed_at if remediation else None
    if finding.status == WorkflowStatus.RESOLVED and (closed_at is None or seen_last >= closed_at):
        previous = {"status": finding.status}
        finding.status = WorkflowStatus.OPEN.value
        if remediation is not None:
            previous["verification_status"] = remediation.verification_status
            remediation.status = WorkflowStatus.OPEN.value
            remediation.verification_status = VerificationStatus.FAILED.value
            remediation.completed_at = None
        audit.record_event(
            db,
            entity_type="finding",
            entity_id=finding.id,
            action="finding_reopened_by_scan",
            actor=actor,
            previous=previous,
            new={
                "status": "open",
                "verification_status": "failed",
                "reason": f"observed again on {seen_last.isoformat()} after resolution",
            },
        )
    return finding, False


def run_import(
    db: Session,
    *,
    content: bytes,
    filename: str,
    source: ImportSource,
    mode: ImportMode,
    actor: str,
    settings: Settings | None = None,
) -> ImportJob:
    settings = settings or get_settings()
    clean_name = safe_filename(filename)
    if len(content) > settings.max_upload_bytes:
        raise PayloadTooLargeError(
            f"File exceeds the {settings.max_upload_bytes} bytes upload limit"
        )
    job = ImportJob(
        source=source.value,
        filename=clean_name,
        mode=mode.value,
        status="failed",
        file_sha256=hashlib.sha256(content).hexdigest(),
        actor=actor,
        total_rows=0,
        imported=0,
        updated=0,
        rejected=0,
        duplicates=0,
        errors=[],
        warnings=[],
    )
    try:
        check_extension(clean_name, source)
        text, warnings = decode(content)
        parsed = PARSERS[source](text, settings.max_import_rows)
    except ImportRejectedError as exc:
        job.errors = [{"line": None, "reasons": [exc.message], "details": exc.details}]
        _persist_failed_job(db, job)
        raise ImportRejectedError(
            exc.message, {"import_job_id": job.id, **(exc.details or {})}
        ) from exc

    job.warnings = warnings + parsed.warnings
    errors: list[dict] = list(parsed.pre_rejected)
    valid: list[tuple[int, FindingRecord]] = []
    seen: dict[tuple, int] = {}
    duplicate_lines: list[str] = []
    for line, raw in parsed.rows:
        record, messages = validate_row(raw, mode)
        if record is None:
            errors.append({"line": line, "reasons": messages})
            continue
        if record.business_key in seen:
            duplicate_lines.append(f"line {line} duplicates line {seen[record.business_key]}")
            continue
        seen[record.business_key] = line
        valid.append((line, record))

    job.total_rows = len(parsed.rows) + len(parsed.pre_rejected)
    job.rejected = len(errors)
    job.duplicates = len(duplicate_lines)
    job.errors = errors[:MAX_ERRORS_STORED]
    if len(errors) > MAX_ERRORS_STORED:
        job.warnings.append(f"{len(errors) - MAX_ERRORS_STORED} additional errors truncated")
    if duplicate_lines:
        job.warnings.append("In-file duplicates ignored: " + "; ".join(duplicate_lines[:50]))

    observed_at = utcnow()
    is_demo = mode == ImportMode.DEMO
    try:
        assets: dict = {}
        vulns: dict = {}
        to_rescore: set[int] = set()
        context_assets: set[int] = set()
        context_vulns: set[int] = set()
        for _line, rec in valid:
            asset, asset_ctx = _upsert_asset(db, rec, is_demo, actor, assets)
            vuln, vuln_ctx = _upsert_vulnerability(db, rec, is_demo, actor, vulns)
            finding, created = _upsert_finding(
                db, rec, asset, vuln, is_demo, source.value, observed_at, actor
            )
            if asset_ctx:
                context_assets.add(asset.id)
            if vuln_ctx:
                context_vulns.add(vuln.id)
            to_rescore.add(finding.id)
            if created:
                job.imported += 1
            else:
                job.updated += 1
        if context_assets or context_vulns:
            to_rescore |= set(
                db.scalars(
                    select(Finding.id).where(
                        Finding.asset_id.in_(context_assets)
                        | Finding.vulnerability_id.in_(context_vulns)
                    )
                )
            )
        db.flush()
        rescore_findings(db, to_rescore, actor=actor, settings=settings)
        job.status = "completed"
        db.add(job)
        db.flush()
        audit.record_event(
            db,
            entity_type="import_job",
            entity_id=job.id,
            action="import_completed",
            actor=actor,
            new={
                "filename": clean_name,
                "source": source.value,
                "mode": mode.value,
                "imported": job.imported,
                "updated": job.updated,
                "rejected": job.rejected,
                "duplicates": job.duplicates,
            },
        )
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        log.exception("Import failed, transaction rolled back")
        job = ImportJob(
            source=job.source,
            filename=job.filename,
            file_sha256=job.file_sha256,
            mode=job.mode,
            status="failed",
            actor=actor,
            total_rows=job.total_rows,
            imported=0,
            updated=0,
            rejected=job.rejected,
            duplicates=job.duplicates,
            warnings=job.warnings,
            errors=[
                {
                    "line": None,
                    "reasons": [f"database error, nothing imported: {type(exc).__name__}"],
                }
            ],
        )
        _persist_failed_job(db, job)
        raise ImportRejectedError(
            "Database error: the import was rolled back", {"import_job_id": job.id}
        ) from exc
    return job


def _persist_failed_job(db: Session, job: ImportJob) -> None:
    db.add(job)
    db.flush()
    audit.record_event(
        db,
        entity_type="import_job",
        entity_id=job.id,
        action="import_failed",
        actor=job.actor,
        new={"filename": job.filename, "errors": job.errors[:5]},
    )
    db.commit()
