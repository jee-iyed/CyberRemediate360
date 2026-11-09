import pytest
from conftest import make_csv
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.core.domain import ImportMode, ImportSource
from app.core.errors import ImportRejectedError, PayloadTooLargeError
from app.models import Asset, AuditEvent, Finding, ImportJob, Remediation, Vulnerability
from app.services.ingestion import run_import
from app.services.remediation import create_remediation, update_remediation

ROW1 = "AST-001,web-01,192.0.2.10,CVE-2021-44228,10.0,internet,critical,open"
ROW2 = "AST-002,db-01,192.0.2.20,CVE-2014-0160,7.5,internal,high,open"


def do_import(
    db, content, mode=ImportMode.PRODUCTION, source=ImportSource.NORMALIZED_CSV, name="scan.csv"
):
    return run_import(db, content=content, filename=name, source=source, mode=mode, actor="t")


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_valid_csv_import(db):
    job = do_import(db, make_csv(ROW1, ROW2))
    assert (job.status, job.imported, job.updated, job.rejected) == ("completed", 2, 0, 0)
    assert count(db, Asset) == 2 and count(db, Vulnerability) == 2 and count(db, Finding) == 2
    finding = db.scalar(
        select(Finding).join(Finding.vulnerability).where(Vulnerability.cve_id == "CVE-2021-44228")
    )
    assert finding.risk_score == 85.0 and finding.priority == "P1"
    assert finding.first_seen is not None and finding.last_seen is not None
    assert isinstance(finding.vulnerability.cvss_score, float)


def test_legacy_sample_file_in_demo_mode(db, sample_bytes):
    job = do_import(db, sample_bytes("vulnerabilities.csv"), mode=ImportMode.DEMO)
    assert job.imported == 4 and job.rejected == 0
    assert all(f.is_demo for f in db.scalars(select(Finding)))
    with pytest.raises(ImportRejectedError):
        pass_through = do_import(db, b"", mode=ImportMode.DEMO)  # noqa: F841


def test_demo_cves_rejected_in_production_mode(db, sample_bytes):
    job = do_import(db, sample_bytes("vulnerabilities.csv"))
    assert job.imported == 0 and job.rejected == 4
    assert "demo mode" in job.errors[0]["reasons"][0]


def test_invalid_rows_report_lines_and_reasons(db, sample_bytes):
    job = do_import(db, sample_bytes("invalid_examples.csv"), mode=ImportMode.DEMO)
    assert job.imported == 1 and job.rejected == 5 and job.duplicates == 1
    by_line = {e["line"]: " ".join(e["reasons"]) for e in job.errors}
    assert "CVSS" in by_line[2]
    assert "IP address" in by_line[3]
    assert "CVE" in by_line[4]
    assert "hostname" in by_line[5]
    assert "exposure" in by_line[6] and "status" in by_line[6]


def test_idempotent_reimport_and_upsert(db):
    content = make_csv(ROW1, ROW2)
    do_import(db, content)
    second = do_import(db, content)
    assert (second.imported, second.updated) == (0, 2)
    assert count(db, Finding) == 2 and count(db, Asset) == 2
    # UPSERT: changed asset context updates the asset and rescoring follows
    third = do_import(db, make_csv(ROW1.replace("internet", "isolated")))
    assert third.updated == 1
    asset = db.scalar(select(Asset).where(Asset.asset_key == "AST-001"))
    db.refresh(asset)
    assert asset.exposure == "isolated"
    finding = asset.findings[0]
    db.refresh(finding)
    assert finding.risk_score == 65.0
    actions = set(db.scalars(select(AuditEvent.action)))
    assert {"asset_updated_by_import", "priority_changed", "import_completed"} <= actions


def test_same_cve_on_two_ports_is_two_findings(db):
    header = "asset_id,hostname,ip_address,cve_id,cvss_score,port"
    job = do_import(
        db,
        make_csv(
            "A1,h1,192.0.2.1,CVE-2020-1234,5.0,443",
            "A1,h1,192.0.2.1,CVE-2020-1234,5.0,8443",
            "A1,h1,192.0.2.1,CVE-2020-1234,5.0,443",
            header=header,
        ),
    )
    assert job.imported == 2 and job.duplicates == 1


def test_absent_finding_is_not_closed(db):
    do_import(db, make_csv(ROW1, ROW2))
    do_import(db, make_csv(ROW1))
    statuses = set(db.scalars(select(Finding.status)))
    assert statuses == {"open"}


def test_resolved_finding_reopened_when_seen_again(db):
    header = "asset_id,hostname,ip_address,cve_id,cvss_score,last_seen"
    do_import(db, make_csv("A1,h1,192.0.2.1,CVE-2020-1234,5.0,2026-01-01", header=header))
    finding = db.scalar(select(Finding))
    rem = create_remediation(
        db, {"finding_id": finding.id, "owner": "o", "action": "patch"}, actor="t"
    )
    update_remediation(db, rem.id, {"status": "resolved", "evidence": "rescan clean"}, actor="t")
    # older observation (before closure): stays resolved
    do_import(db, make_csv("A1,h1,192.0.2.1,CVE-2020-1234,5.0,2026-01-02", header=header))
    db.refresh(finding)
    assert finding.status == "resolved"
    # observation without date = now, after closure -> regression
    do_import(db, make_csv("A1,h1,192.0.2.1,CVE-2020-1234,5.0,", header=header))
    db.refresh(finding)
    rem = db.get(Remediation, rem.id)
    db.refresh(rem)
    assert finding.status == "open" and rem.verification_status == "failed"
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "finding_reopened_by_scan"))


def test_malformed_and_empty_files_create_failed_jobs(db):
    for content, source, name in [
        (b"", ImportSource.NORMALIZED_CSV, "e.csv"),
        (b"{bad", ImportSource.NORMALIZED_JSON, "b.json"),
        (b"a,b\n1,2\n", ImportSource.NORMALIZED_CSV, "x.csv"),
    ]:
        with pytest.raises(ImportRejectedError) as exc:
            do_import(db, content, source=source, name=name)
        assert "import_job_id" in exc.value.details
    assert count(db, ImportJob) == 3
    assert set(db.scalars(select(ImportJob.status))) == {"failed"}
    assert count(db, Finding) == 0


def test_extension_and_size_limits(db, monkeypatch):
    with pytest.raises(ImportRejectedError):
        do_import(db, make_csv(ROW1), name="scan.exe")
    with pytest.raises(ImportRejectedError):
        do_import(db, make_csv(ROW1), source=ImportSource.NORMALIZED_JSON, name="scan.csv")
    from app.core.config import get_settings

    settings = get_settings().model_copy(update={"max_upload_bytes": 1024})
    with pytest.raises(PayloadTooLargeError):
        run_import(
            db,
            content=b"x" * 2048,
            filename="a.csv",
            source=ImportSource.NORMALIZED_CSV,
            mode=ImportMode.PRODUCTION,
            actor="t",
            settings=settings,
        )


def test_json_import(db, sample_bytes):
    job = do_import(
        db,
        sample_bytes("demo_findings.json"),
        mode=ImportMode.DEMO,
        source=ImportSource.NORMALIZED_JSON,
        name="demo_findings.json",
    )
    assert job.imported == 2
    assert db.scalar(select(Asset).where(Asset.ip_address == "2001:db8::25"))


def test_nessus_import(db, sample_bytes):
    job = do_import(
        db,
        sample_bytes("nessus_export_sample.csv"),
        mode=ImportMode.DEMO,
        source=ImportSource.NESSUS_CSV,
        name="nessus.csv",
    )
    assert job.imported == 3 and job.rejected == 1
    asset = db.scalar(select(Asset).where(Asset.asset_key == "NES-192.0.2.150"))
    assert asset.exposure == "unknown"
    assert "exposure" in asset.findings[0].risk_explanation["missing_inputs"]


def test_transaction_rollback_on_db_error(db, monkeypatch):
    import app.services.ingestion as ingestion

    def boom(*args, **kwargs):
        raise IntegrityError("stmt", {}, Exception("forced"))

    monkeypatch.setattr(ingestion, "rescore_findings", boom)
    with pytest.raises(ImportRejectedError):
        do_import(db, make_csv(ROW1, ROW2))
    assert count(db, Finding) == 0 and count(db, Asset) == 0
    job = db.scalar(select(ImportJob))
    assert job.status == "failed" and job.imported == 0


def test_sql_integrity_constraints(db):
    db.add(Vulnerability(cve_id="CVE-2020-0001", cvss_score=11.0, is_demo=False))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    db.add(
        Finding(asset_id=999, vulnerability_id=999, location_key="", status="open", is_demo=False)
    )
    with pytest.raises(IntegrityError):  # foreign keys enforced
        db.commit()
    db.rollback()
    do_import(db, make_csv(ROW1))
    f = db.scalar(select(Finding))
    db.add(
        Finding(
            asset_id=f.asset_id,
            vulnerability_id=f.vulnerability_id,
            location_key="",
            status="open",
            is_demo=False,
        )
    )
    with pytest.raises(IntegrityError):  # business key unique
        db.commit()
    db.rollback()
    f.status = "closed"
    with pytest.raises(IntegrityError):  # status check constraint
        db.commit()
    db.rollback()
