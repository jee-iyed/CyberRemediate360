"""Load the fictional "Helios Logistics" demo scenario (idempotent).

* Imports the sample files in **demo mode** (records flagged ``is_demo``).
* Creates remediation plans and drives a few through the workflow so every status,
  an overdue item and the audit trail are visible in the dashboard.

Running it twice creates no duplicates (imports become UPSERT updates, existing
remediation plans are skipped).

Usage (project root):  python scripts/seed_demo.py
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from init_db import init_database  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.database import SessionLocal  # noqa: E402
from app.core.domain import ImportMode, ImportSource  # noqa: E402
from app.core.errors import DomainError  # noqa: E402
from app.core.timeutils import utcnow  # noqa: E402
from app.models import Asset, Finding, Remediation, Vulnerability  # noqa: E402
from app.services.ingestion import run_import  # noqa: E402
from app.services.remediation import create_remediation, update_remediation  # noqa: E402

SAMPLES = ROOT / "data" / "samples"
ACTOR = "demo-seed"
IMPORTS = [
    ("vulnerabilities.csv", ImportSource.NORMALIZED_CSV),
    ("demo_scenario.csv", ImportSource.NORMALIZED_CSV),
    ("demo_findings.json", ImportSource.NORMALIZED_JSON),
    ("nessus_export_sample.csv", ImportSource.NESSUS_CSV),
]

# (asset_key, cve_id, location_key, owner, action, workflow steps)
PLANS = [
    (
        "HLX-VPN-01",
        "CVE-DEMO-016",
        "tcp/443",
        "Network Team",
        "Apply vendor firmware 9.0.4 to the VPN appliance",
        [],
    ),
    (
        "HLX-WEB-01",
        "CVE-DEMO-010",
        "tcp/443",
        "E-commerce Team",
        "Upgrade DemoFramework to 2.1.1 and redeploy",
        [{"status": "in_progress", "notes": "Change request CHG-DEMO-101 approved"}],
    ),
    (
        "HLX-API-01",
        "CVE-DEMO-012",
        "tcp/8443",
        "Platform Team",
        "Disable vulnerable gateway plugin until patched",
        [
            {
                "status": "mitigated",
                "justification": "WAF rule DEMO-WAF-12 blocks the bypass path; patch planned",
            }
        ],
    ),
    (
        "HLX-ERP-01",
        "CVE-DEMO-013",
        "tcp/8080",
        "Finance IT",
        "Install ERP hotfix 7.2.1",
        [
            {"status": "in_progress"},
            {
                "status": "resolved",
                "evidence": "Fictional rescan 2026-11-05: hotfix 7.2.1 detected",
            },
            {"verification_status": "verified"},
        ],
    ),
    (
        "HLX-PRN-01",
        "CVE-DEMO-018",
        "tcp/80",
        "Facilities",
        "Change printer admin password",
        [
            {
                "status": "accepted",
                "justification": "Printer VLAN isolated; device replacement planned in Q1",
                "risk_acceptance_expires_at": "+90d",
            }
        ],
    ),
    (
        "HLX-MAIL-01",
        "CVE-DEMO-019",
        "tcp/25",
        "Messaging Team",
        "Review SMTP banner configuration",
        [
            {
                "status": "false_positive",
                "justification": "Banner shows a public relay name, not an internal hostname",
            }
        ],
    ),
    ("HLX-DEV-01", "CVE-DEMO-017", "tcp/8080", "DevOps Team", "Upgrade CI server to 4.0", []),
]


def _resolve_step(step: dict) -> dict:
    out = dict(step)
    if out.get("risk_acceptance_expires_at") == "+90d":
        out["risk_acceptance_expires_at"] = utcnow() + timedelta(days=90)
    return out


def seed() -> None:
    init_database()
    with SessionLocal() as db:
        for name, source in IMPORTS:
            content = (SAMPLES / name).read_bytes()
            try:
                job = run_import(
                    db,
                    content=content,
                    filename=name,
                    source=source,
                    mode=ImportMode.DEMO,
                    actor=ACTOR,
                )
                print(
                    f"{name:28} new={job.imported:3} updated={job.updated:3} "
                    f"rejected={job.rejected:3} duplicates={job.duplicates:3}"
                )
            except DomainError as exc:
                print(f"{name:28} FAILED: {exc.message}")

        created = 0
        for asset_key, cve, location, owner, action, steps in PLANS:
            finding = db.scalar(
                select(Finding)
                .join(Finding.asset)
                .join(Finding.vulnerability)
                .where(
                    Asset.asset_key == asset_key,
                    Vulnerability.cve_id == cve,
                    Finding.location_key == location,
                )
            )
            if finding is None:
                print(f"skip plan: finding {asset_key}/{cve}/{location} not found")
                continue
            if db.scalar(select(Remediation.id).where(Remediation.finding_id == finding.id)):
                continue
            rem = create_remediation(
                db, {"finding_id": finding.id, "owner": owner, "action": action}, actor=ACTOR
            )
            for step in steps:
                update_remediation(db, rem.id, _resolve_step(step), actor=ACTOR)
            created += 1
        print(f"Remediation plans created: {created}")


if __name__ == "__main__":
    seed()
