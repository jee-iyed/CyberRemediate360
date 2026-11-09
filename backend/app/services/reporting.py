"""CISO (RSSI) reporting: PDF, CSV and JSON exports built from the same data snapshot.

All figures come from ``build_report_data``, which reads the database once; the PDF, CSV
and JSON therefore show identical, verifiable values.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.domain import ACTIVE_STATUSES, cvss_severity
from app.core.timeutils import utcnow
from app.models import ImportJob
from app.services import dashboard

BRAND = colors.HexColor("#0B3D5C")
ACCENT = colors.HexColor("#14B8A6")
LIMITATIONS = [
    "The priority score is an internal ranking aid (0-100), not a probability of compromise.",
    "Threat signals (CISA KEV, EPSS) are used only when supplied with a documented source; "
    "the platform does not fetch them online.",
    "Findings absent from a new scan are never closed automatically; closure requires a "
    "remediation decision with evidence.",
    "Trend charts use recorded first_seen / completed_at dates only; records without dates "
    "are excluded and counted separately.",
    "Demo records (CVE-DEMO-*, documentation IP ranges) are fictional and flagged is_demo.",
]


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def build_report_data(db: Session, include_demo: bool = True) -> dict:
    now = utcnow()
    summary = dashboard.summary(db, include_demo)
    trend = dashboard.trends(db, include_demo)
    findings = dashboard._load_findings(db, include_demo)
    active = {s.value for s in ACTIVE_STATUSES}
    rows = []
    for f in sorted(findings, key=lambda x: (x.risk_score or 0), reverse=True):
        rem = f.remediation
        rows.append(
            {
                "finding_id": f.id,
                "asset_key": f.asset.asset_key,
                "hostname": f.asset.hostname,
                "ip_address": f.asset.ip_address,
                "environment": f.asset.environment,
                "exposure": f.asset.exposure,
                "business_criticality": f.asset.business_criticality,
                "cve_id": f.vulnerability.cve_id,
                "title": f.vulnerability.title,
                "cvss_score": f.vulnerability.cvss_score,
                "cvss_version": f.vulnerability.cvss_version,
                "cvss_severity": cvss_severity(f.vulnerability.cvss_score),
                "kev": f.vulnerability.kev,
                "epss_score": f.vulnerability.epss_score,
                "location": f.location_key or None,
                "status": f.status,
                "risk_score": f.risk_score,
                "priority": f.priority,
                "first_seen": _iso(f.first_seen),
                "last_seen": _iso(f.last_seen),
                "remediation_owner": rem.owner if rem else None,
                "remediation_status": rem.status if rem else None,
                "due_date": _iso(rem.due_date) if rem else None,
                "completed_at": _iso(rem.completed_at) if rem else None,
                "verification_status": rem.verification_status if rem else None,
                "overdue": dashboard.is_overdue(rem, now),
                "is_demo": f.is_demo,
            }
        )
    jobs = list(db.scalars(select(ImportJob).order_by(ImportJob.timestamp.desc()).limit(20)))
    return {
        "title": "CyberRemediate 360 - Vulnerability & Cyber Risk Report",
        "generated_at": now.isoformat(),
        "summary": summary,
        "trends": trend,
        "findings": rows,
        "top_risks": [r for r in rows if r["status"] in active][:10],
        "overdue": [r for r in rows if r["overdue"]],
        "imports": [
            {
                "id": j.id,
                "timestamp": _iso(j.timestamp),
                "filename": j.filename,
                "source": j.source,
                "mode": j.mode,
                "status": j.status,
                "imported": j.imported,
                "updated": j.updated,
                "rejected": j.rejected,
                "duplicates": j.duplicates,
            }
            for j in jobs
        ],
        "limitations": LIMITATIONS,
    }


# ---------------------------------------------------------------------------- CSV / JSON
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralise spreadsheet formula injection (OWASP CSV injection)."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def render_csv(data: dict) -> bytes:
    rows = data["findings"]
    buffer = io.StringIO()
    fieldnames = list(rows[0].keys()) if rows else ["finding_id"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: _csv_safe(v) for k, v in row.items()})
    return buffer.getvalue().encode("utf-8-sig")


def render_json(data: dict) -> bytes:
    return json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------------- PDF
def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text)), style)


def _table(header: list[str], rows: list[list], widths: list[float] | None = None) -> Table:
    styles = getSampleStyleSheet()
    cell = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=7.5, leading=9)
    body = [[_p(h, cell) for h in header]] + [
        [_p("" if v is None else v, cell) for v in r] for r in rows
    ]
    table = Table(body, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawString(
        1.5 * cm, 1 * cm, "CyberRemediate 360 - internal report - generated from " "platform data"
    )
    canvas.drawRightString(A4[0] - 1.5 * cm, 1 * cm, f"Page {doc.page}")
    canvas.restoreState()


def render_pdf(data: dict) -> bytes:
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=BRAND)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=BRAND)
    body = styles["BodyText"]
    s = data["summary"]
    mttr = s["mean_time_to_resolve_days"]
    story = [
        _p(data["title"], h1),
        _p(f"Generated at {data['generated_at']} (UTC)", body),
    ]
    if s["data_quality"]["demo_findings"]:
        story.append(
            _p(
                f"NOTICE: {s['data_quality']['demo_findings']} finding(s) in this report are "
                "fictional demonstration data (is_demo).",
                body,
            )
        )
    story += [Spacer(1, 8), _p("1. Executive summary", h2)]
    story.append(
        _p(
            f"{s['open_findings']} active finding(s) across {s['total_assets']} asset(s); "
            f"{s['high_critical_open']} active with CVSS >= 7.0 and {s['p1_open']} ranked P1. "
            f"{s['overdue_remediations']} remediation(s) are overdue. "
            f"{s['resolved_findings']} finding(s) resolved, "
            f"{s['accepted_findings']} risk-accepted, "
            f"{s['false_positive_findings']} false positive(s).",
            body,
        )
    )
    kpis = [
        ["Total assets", s["total_assets"]],
        ["Total findings", s["total_findings"]],
        ["Active findings", s["open_findings"]],
        ["Active high/critical (CVSS>=7)", s["high_critical_open"]],
        ["Active P1", s["p1_open"]],
        ["Overdue remediations", s["overdue_remediations"]],
        ["Resolved", s["resolved_findings"]],
        [
            "Mean time to resolve (days)",
            f"{mttr['value']} (n={mttr['sample_size']})",
        ],
    ]
    story += [_table(["Indicator", "Value"], kpis, [9 * cm, 6 * cm])]

    story += [_p("2. Inventory and coverage", h2)]
    cov = s["remediation_coverage"]
    story.append(
        _p(
            f"{s['total_assets']} assets in inventory. {cov['active_with_plan']} of "
            f"{cov['active_total']} active findings have a remediation plan.",
            body,
        )
    )
    story.append(_table(["Status", "Findings"], sorted(s["by_status"].items())))
    story.append(Spacer(1, 6))
    story.append(_table(["CVSS severity (active)", "Findings"], sorted(s["by_severity"].items())))

    story += [_p("3. Top risks", h2)]
    story.append(
        _table(
            ["Priority", "Score", "CVE", "CVSS", "Asset", "Exposure", "Criticality", "Status"],
            [
                [
                    r["priority"],
                    r["risk_score"],
                    r["cve_id"],
                    r["cvss_score"],
                    r["hostname"],
                    r["exposure"],
                    r["business_criticality"],
                    r["status"],
                ]
                for r in data["top_risks"]
            ],
        )
    )

    story += [_p("4. Remediation priorities, owners and due dates", h2)]
    planned = [r for r in data["top_risks"] if r["remediation_owner"]]
    story.append(
        _table(
            ["Priority", "CVE", "Asset", "Owner", "Status", "Due (UTC)"],
            [
                [
                    r["priority"],
                    r["cve_id"],
                    r["hostname"],
                    r["remediation_owner"],
                    r["remediation_status"],
                    (r["due_date"] or "")[:10],
                ]
                for r in planned
            ],
        )
        if planned
        else _p("No remediation plan exists for the top risks.", body)
    )
    unplanned = [r for r in data["top_risks"] if not r["remediation_owner"]]
    if unplanned:
        story.append(_p(f"{len(unplanned)} top risk(s) have no remediation plan yet.", body))

    story += [_p("5. Overdue remediations", h2)]
    story.append(
        _table(
            ["CVE", "Asset", "Owner", "Due (UTC)", "Status", "Priority"],
            [
                [
                    r["cve_id"],
                    r["hostname"],
                    r["remediation_owner"],
                    (r["due_date"] or "")[:10],
                    r["remediation_status"],
                    r["priority"],
                ]
                for r in data["overdue"]
            ],
        )
        if data["overdue"]
        else _p("No overdue remediation.", body)
    )

    story += [_p("6. Risk evolution (weekly, recorded dates only)", h2)]
    series = data["trends"]["series"]
    story.append(
        _table(
            ["Week starting", "New findings", "Closed findings", "Imports"],
            [
                [w["week_start"], w["new_findings"], w["closed_findings"], w["imports"]]
                for w in series
            ],
        )
        if series
        else _p("No dated events recorded yet.", body)
    )

    story += [_p("7. Limitations and data quality", h2)]
    dq = s["data_quality"]
    story.append(
        _p(
            f"{dq['findings_with_incomplete_scoring_inputs']} finding(s) scored with "
            "missing inputs; "
            f"{dq['findings_without_first_seen']} without first_seen date; "
            f"{dq['real_findings']} imported real finding(s), "
            f"{dq['demo_findings']} demo finding(s).",
            body,
        )
    )
    for item in data["limitations"]:
        story.append(_p(f"- {item}", body))

    story += [PageBreak(), _p("Appendix - technical detail", h2)]
    story.append(
        _p(
            "Scoring model cr360-additive-v1: severity (CVSS/10 x 50) + exposure "
            "(20/8/0) + business criticality (15/10/5/0) + threat (max of KEV 15, "
            "EPSS 10/5, capped 15). P1 >= 75, P2 >= 55, P3 >= 35.",
            body,
        )
    )
    story.append(
        _table(
            ["ID", "CVE", "Asset", "Location", "CVSS", "Score", "Prio", "Status", "First seen"],
            [
                [
                    r["finding_id"],
                    r["cve_id"],
                    r["asset_key"],
                    r["location"],
                    r["cvss_score"],
                    r["risk_score"],
                    r["priority"],
                    r["status"],
                    (r["first_seen"] or "")[:10],
                ]
                for r in data["findings"]
            ],
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        _table(
            ["Import", "Time (UTC)", "File", "Mode", "Status", "New", "Upd.", "Rej.", "Dup."],
            [
                [
                    j["id"],
                    (j["timestamp"] or "")[:16],
                    j["filename"],
                    j["mode"],
                    j["status"],
                    j["imported"],
                    j["updated"],
                    j["rejected"],
                    j["duplicates"],
                ]
                for j in data["imports"]
            ],
        )
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title="CyberRemediate 360 - CISO report",
        author="CyberRemediate 360",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
