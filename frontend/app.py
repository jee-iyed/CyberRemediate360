"""CyberRemediate 360 - SOC / GRC dashboard (Streamlit).

All data is fetched from the FastAPI backend (``CR360_API_URL``); no KPI is hard-coded.

Run (project root):  streamlit run frontend/app.py
"""

from __future__ import annotations

from datetime import UTC, datetime, time, timedelta

import pandas as pd
import plotly.express as px
import streamlit as st
from api_client import ApiClient, ApiError

st.set_page_config(page_title="CyberRemediate 360", page_icon="🛡️", layout="wide")

BRAND = "#0B3D5C"
ACCENT = "#14B8A6"
SEVERITY_COLORS = {
    "critical": "#B91C1C",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#2563EB",
    "none": "#64748B",
    "unknown": "#94A3B8",
}
PRIORITY_COLORS = {
    "P1": "#B91C1C",
    "P2": "#EA580C",
    "P3": "#CA8A04",
    "P4": "#2563EB",
    "unscored": "#94A3B8",
}
STATUSES = ["open", "in_progress", "mitigated", "resolved", "accepted", "false_positive"]

st.markdown(
    f"""
    <style>
      .block-container {{padding-top: 1.6rem; max-width: 1400px;}}
      .cr-header {{background: linear-gradient(90deg, {BRAND}, #115E7A); color: white;
                   padding: 14px 20px; border-radius: 10px; margin-bottom: 14px;}}
      .cr-header h1 {{color: white; font-size: 1.45rem; margin: 0;}}
      .cr-header p {{color: #CFFAFE; margin: 2px 0 0 0; font-size: 0.9rem;}}
      .cr-kpi {{border: 1px solid #E2E8F0; border-left: 5px solid {ACCENT}; border-radius: 8px;
                padding: 10px 14px; background: rgba(148,163,184,0.06);}}
      .cr-kpi .v {{font-size: 1.7rem; font-weight: 700;}}
      .cr-kpi .l {{font-size: 0.8rem; color: #64748B; text-transform: uppercase;}}
      .cr-demo {{background:#FEF3C7; color:#92400E; padding:6px 10px; border-radius:6px;
                 font-size:0.85rem;}}
    </style>
    """,
    unsafe_allow_html=True,
)


# ------------------------------------------------------------------------------ helpers
def header(title: str, subtitle: str) -> None:
    st.markdown(
        f'<div class="cr-header"><h1>🛡️ {title}</h1><p>{subtitle}</p></div>', unsafe_allow_html=True
    )


def kpi(col, label: str, value, border: str = ACCENT) -> None:
    col.markdown(
        f'<div class="cr-kpi" style="border-left-color:{border}"><div class="l">{label}</div>'
        f'<div class="v">{value}</div></div>',
        unsafe_allow_html=True,
    )


def api() -> ApiClient:
    return ApiClient(actor=st.session_state.get("actor") or "dashboard-user")


def call(fn, *args, **kwargs):
    """Run an API call and display a useful error instead of a stack trace."""
    try:
        return fn(*args, **kwargs)
    except ApiError as exc:
        st.error(f"API error{f' {exc.status}' if exc.status else ''}: {exc.message}")
        if exc.details:
            with st.expander("Details"):
                st.json(exc.details)
        return None


def demo_filter() -> bool | None:
    choice = st.session_state.get("data_scope", "All data")
    return {"All data": None, "Real imports only": False, "Demo data only": True}[choice]


def include_demo() -> bool:
    return demo_filter() is not False


def findings_df(**params) -> pd.DataFrame:
    items = call(api().get_all, "/findings", is_demo=demo_filter(), **params)
    return pd.DataFrame(items or [])


def empty_state(message: str) -> None:
    st.info(
        f"{message}\n\nTip: run `python scripts/seed_demo.py` to load the fictional demo "
        "scenario, or use **Import Reports** to upload a scan."
    )


# -------------------------------------------------------------------------------- pages
def page_overview() -> None:
    header("Security Posture Overview", "Live KPIs computed by the API from the database")
    s = call(api().get, "/dashboard/summary", include_demo=include_demo())
    if s is None:
        return
    if s["data_quality"]["demo_findings"] and include_demo():
        st.markdown(
            f'<span class="cr-demo">⚠ {s["data_quality"]["demo_findings"]} demo '
            "(fictional) finding(s) included. Switch the data scope in the sidebar to "
            "exclude them.</span>",
            unsafe_allow_html=True,
        )
    cols = st.columns(6)
    kpi(cols[0], "Assets", s["total_assets"])
    kpi(cols[1], "Active findings", s["open_findings"])
    kpi(cols[2], "High/Critical (CVSS≥7)", s["high_critical_open"], "#EA580C")
    kpi(cols[3], "P1 active", s["p1_open"], "#B91C1C")
    kpi(cols[4], "Overdue remediations", s["overdue_remediations"], "#B91C1C")
    kpi(cols[5], "Resolved", s["resolved_findings"], "#16A34A")
    if not s["total_findings"]:
        empty_state("No finding in the database yet.")
        return
    st.write("")
    left, right = st.columns(2)
    sev = pd.DataFrame([{"severity": k, "findings": v} for k, v in s["by_severity"].items()])
    if not sev.empty:
        left.plotly_chart(
            px.pie(
                sev,
                names="severity",
                values="findings",
                hole=0.5,
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                title="Active findings by CVSS severity",
            ),
            use_container_width=True,
        )
    stat = pd.DataFrame([{"status": k, "findings": v} for k, v in s["by_status"].items()])
    right.plotly_chart(
        px.bar(
            stat,
            x="status",
            y="findings",
            title="Findings by workflow status",
            color_discrete_sequence=[BRAND],
        ),
        use_container_width=True,
    )

    st.subheader("Top 10 assets at risk")
    top = pd.DataFrame(s["top_assets"])
    if top.empty:
        st.success("No active finding.")
    else:
        st.dataframe(
            top.drop(columns=["asset_id"]),
            hide_index=True,
            use_container_width=True,
            column_config={
                "max_risk_score": st.column_config.ProgressColumn(
                    "Max risk score", min_value=0, max_value=100, format="%.1f"
                )
            },
        )

    st.subheader("Trends (recorded dates only)")
    t = call(api().get, "/dashboard/trends", include_demo=include_demo())
    if t and t["series"]:
        df = pd.DataFrame(t["series"]).melt("week_start", var_name="metric", value_name="count")
        st.plotly_chart(
            px.line(df, x="week_start", y="count", color="metric", markers=True),
            use_container_width=True,
        )
        if t["excluded"]["findings_without_first_seen"]:
            st.caption(
                f"{t['excluded']['findings_without_first_seen']} finding(s) without a "
                "first_seen date are excluded from the trend (legacy records)."
            )
    cov, mttr, dq = s["remediation_coverage"], s["mean_time_to_resolve_days"], s["data_quality"]
    c1, c2, c3 = st.columns(3)
    c1.metric(
        "Active findings with a remediation plan",
        f"{cov['active_with_plan']}/{cov['active_total']}",
    )
    c2.metric(
        "Mean time to resolve (days)",
        mttr["value"] if mttr["value"] is not None else "n/a",
        help=f"Sample size: {mttr['sample_size']} resolved finding(s) with known dates",
    )
    c3.metric("Findings scored with missing inputs", dq["findings_with_incomplete_scoring_inputs"])


def page_assets() -> None:
    header("Asset Inventory", "Assets, exposure and business criticality")
    c1, c2, c3 = st.columns([2, 1, 1])
    q = c1.text_input("Search (hostname, key, IP, owner)")
    exposure = c2.selectbox("Exposure", ["", "internet", "internal", "isolated", "unknown"])
    crit = c3.selectbox("Criticality", ["", "critical", "high", "medium", "low", "unknown"])
    items = call(
        api().get_all, "/assets", q=q, exposure=exposure, criticality=crit, is_demo=demo_filter()
    )
    if not items:
        empty_state("No asset matches.")
    else:
        df = pd.DataFrame(items)
        st.dataframe(
            df[
                [
                    "id",
                    "asset_key",
                    "hostname",
                    "ip_address",
                    "owner",
                    "environment",
                    "exposure",
                    "business_criticality",
                    "is_demo",
                ]
            ],
            hide_index=True,
            use_container_width=True,
        )
        options = {f"{a['asset_key']} - {a['hostname']}": a["id"] for a in items}
        choice = st.selectbox("Asset detail", list(options))
        detail = call(api().get, f"/assets/{options[choice]}")
        if detail:
            st.write(f"**{detail['open_findings']}** active finding(s)")
            if detail["findings"]:
                st.dataframe(
                    pd.DataFrame(detail["findings"])[
                        [
                            "id",
                            "cve_id",
                            "cvss_score",
                            "location_key",
                            "status",
                            "risk_score",
                            "priority",
                        ]
                    ],
                    hide_index=True,
                    use_container_width=True,
                )
            with st.form("asset_ctx"):
                st.caption("Update inventory context - findings are re-scored automatically.")
                a, b, c = st.columns(3)
                exp_opts = ["internet", "internal", "isolated", "unknown"]
                crit_opts = ["critical", "high", "medium", "low", "unknown"]
                new_exp = a.selectbox("Exposure", exp_opts, exp_opts.index(detail["exposure"]))
                new_crit = b.selectbox(
                    "Criticality", crit_opts, crit_opts.index(detail["business_criticality"])
                )
                owner = c.text_input("Owner", detail["owner"] or "")
                if st.form_submit_button("Save context"):
                    if call(
                        api().patch,
                        f"/assets/{detail['id']}",
                        {
                            "exposure": new_exp,
                            "business_criticality": new_crit,
                            "owner": owner or None,
                        },
                    ):
                        st.success("Asset updated and findings re-scored.")
    with st.expander("➕ Register a new asset"):
        with st.form("new_asset", clear_on_submit=True):
            a, b, c = st.columns(3)
            key = a.text_input("Asset key*", placeholder="AST-100")
            host = b.text_input("Hostname*", placeholder="srv-01.example.test")
            ip = c.text_input("IP address*", placeholder="192.0.2.100")
            d, e, f, g = st.columns(4)
            env = d.selectbox(
                "Environment", ["production", "staging", "development", "test", "unknown"]
            )
            exp = e.selectbox("Exposure", ["internet", "internal", "isolated", "unknown"])
            crit = f.selectbox("Criticality", ["critical", "high", "medium", "low", "unknown"])
            owner = g.text_input("Owner")
            if st.form_submit_button("Create asset"):
                created = call(
                    api().post,
                    "/assets",
                    {
                        "asset_key": key,
                        "hostname": host,
                        "ip_address": ip,
                        "environment": env,
                        "exposure": exp,
                        "business_criticality": crit,
                        "owner": owner or None,
                    },
                )
                if created:
                    st.success(f"Asset {created['asset_key']} created (id {created['id']}).")


def page_vulnerabilities() -> None:
    header("Vulnerability Explorer", "CVE catalogue with CVSS, CWE and threat signals")
    c1, c2, c3 = st.columns([2, 1, 1])
    q = c1.text_input("Search CVE, title, CWE")
    min_cvss = c2.slider("Minimum CVSS", 0.0, 10.0, 0.0, 0.1)
    kev = c3.selectbox("CISA KEV", ["any", "listed", "not listed"])
    items = call(
        api().get_all,
        "/vulnerabilities",
        q=q,
        min_cvss=min_cvss or None,
        kev={"any": None, "listed": True, "not listed": False}[kev],
        is_demo=demo_filter(),
    )
    if not items:
        empty_state("No vulnerability matches.")
        return
    df = pd.DataFrame(items)
    st.dataframe(
        df[
            [
                "cve_id",
                "title",
                "cvss_score",
                "cvss_version",
                "cvss_vector",
                "cwe_id",
                "kev",
                "epss_score",
                "threat_source",
                "is_demo",
            ]
        ],
        hide_index=True,
        use_container_width=True,
        column_config={"cvss_score": st.column_config.NumberColumn(format="%.1f")},
    )
    st.caption(
        "Threat signals are shown only when supplied with a documented source. "
        "'demo-simulated' signals are fictional."
    )
    scored = df.dropna(subset=["cvss_score"])
    if not scored.empty:
        st.plotly_chart(
            px.histogram(
                scored,
                x="cvss_score",
                nbins=20,
                title="CVSS base score distribution",
                color_discrete_sequence=[BRAND],
            ),
            use_container_width=True,
        )


def page_risk() -> None:
    header("Risk Prioritization", "Internal priority score 0-100 (ranking aid, not a probability)")
    c1, c2, c3 = st.columns([2, 1, 1])
    q = c1.text_input("Search (CVE, hostname, service)")
    status = c2.multiselect("Status", STATUSES, default=["open", "in_progress", "mitigated"])
    priority = c3.multiselect("Priority", ["P1", "P2", "P3", "P4"])
    df = findings_df(q=q, status=status, priority=priority)
    if df.empty:
        empty_state("No finding matches the filters.")
        return
    left, right = st.columns([3, 2])
    left.dataframe(
        df[
            [
                "id",
                "priority",
                "risk_score",
                "cve_id",
                "cvss_score",
                "hostname",
                "location_key",
                "status",
                "is_demo",
            ]
        ],
        hide_index=True,
        use_container_width=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn(
                "Risk score", min_value=0, max_value=100, format="%.1f"
            )
        },
    )
    counts = df["priority"].fillna("unscored").value_counts().reset_index()
    counts.columns = ["priority", "findings"]
    right.plotly_chart(
        px.bar(
            counts,
            x="priority",
            y="findings",
            color="priority",
            color_discrete_map=PRIORITY_COLORS,
            title="Findings by priority",
        ),
        use_container_width=True,
    )
    right.plotly_chart(
        px.scatter(
            df,
            x="cvss_score",
            y="risk_score",
            color="priority",
            color_discrete_map=PRIORITY_COLORS,
            hover_data=["cve_id", "hostname"],
            title="CVSS vs internal priority score",
        ),
        use_container_width=True,
    )

    st.subheader("Why this priority?")
    labels = {
        f"#{r.id} {r.cve_id} on {r.hostname} ({r.priority}, {r.risk_score})": r.id
        for r in df.itertuples()
    }
    detail = call(api().get, f"/findings/{labels[st.selectbox('Finding', list(labels))]}")
    if detail:
        exp = detail["risk_explanation"] or {}
        comp = exp.get("components", {})
        a, b = st.columns([2, 3])
        a.plotly_chart(
            px.bar(
                pd.DataFrame({"component": list(comp), "points": list(comp.values())}),
                x="points",
                y="component",
                orientation="h",
                range_x=[0, 50],
                color_discrete_sequence=[ACCENT],
                title=f"Score {exp.get('score')} → " f"{exp.get('priority')}",
            ),
            use_container_width=True,
        )
        b.markdown("**Calculation**")
        for reason in exp.get("reasons", []):
            b.markdown(f"- {reason}")
        if exp.get("missing_inputs"):
            b.warning("Missing inputs (scored 0, not guessed): " + ", ".join(exp["missing_inputs"]))
        v = detail["vulnerability"]
        b.caption(
            f"CVSS {v['cvss_score']} v{v['cvss_version'] or '?'} · vector "
            f"{v['cvss_vector'] or 'n/a'} · CWE {v['cwe_id'] or 'n/a'} · "
            f"asset exposure {detail['asset']['exposure']} · criticality "
            f"{detail['asset']['business_criticality']}"
        )
        if v.get("threat_source"):
            b.caption(f"Threat signal source: {v['threat_source']}")
        if detail.get("evidence"):
            b.text(f"Evidence: {detail['evidence']}")


def page_remediation() -> None:
    header("Remediation Tracker", "Owners, due dates, workflow and verification")
    only_overdue = st.toggle("Only overdue")
    rems = call(api().get_all, "/remediations", overdue=only_overdue or None)
    if rems:
        df = pd.DataFrame(rems)
        st.dataframe(
            df[
                [
                    "id",
                    "finding_id",
                    "owner",
                    "action",
                    "status",
                    "due_date",
                    "overdue",
                    "verification_status",
                    "completed_at",
                ]
            ],
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No remediation plan yet.")

    tab_new, tab_update = st.tabs(["➕ New plan", "✏️ Update / transition"])
    with tab_new:
        candidates = findings_df(status=["open", "in_progress"])
        planned = {r["finding_id"] for r in (rems or [])}
        if not candidates.empty:
            candidates = candidates[~candidates["id"].isin(planned)]
        if candidates.empty:
            st.caption("Every active finding already has a plan.")
        else:
            opts = {
                f"#{r.id} {r.priority} {r.cve_id} on {r.hostname}": r.id
                for r in candidates.itertuples()
            }
            with st.form("new_rem", clear_on_submit=True):
                fid = st.selectbox("Finding", list(opts))
                owner = st.text_input("Owner*")
                action = st.text_area("Action*", placeholder="Apply vendor patch X.Y")
                solution = st.text_area("Proposed solution")
                use_sla = st.checkbox("Use SLA default due date (by priority)", value=True)
                due = st.date_input("Due date (if not SLA)")
                if st.form_submit_button("Create plan"):
                    payload = {
                        "finding_id": opts[fid],
                        "owner": owner,
                        "action": action,
                        "proposed_solution": solution or None,
                    }
                    if not use_sla:
                        payload["due_date"] = datetime.combine(due, time(), UTC).isoformat()
                    if call(api().post, "/remediations", payload):
                        st.success("Remediation plan created.")
    with tab_update:
        if not rems:
            st.caption("Create a plan first.")
            return
        opts = {
            f"#{r['id']} finding {r['finding_id']} - {r['owner']} ({r['status']})": r for r in rems
        }
        rem = opts[st.selectbox("Remediation", list(opts))]
        st.markdown(
            "**Rules:** *resolved* needs evidence · *mitigated*, *false_positive* and re-opening "
            "need a justification · *accepted* needs a justification and an expiry date "
            "(≤ 365 days)."
        )
        with st.form("upd_rem"):
            a, b = st.columns(2)
            status = a.selectbox("Status", STATUSES, STATUSES.index(rem["status"]))
            verif_opts = ["not_verified", "pending", "verified", "failed"]
            verification = b.selectbox(
                "Verification", verif_opts, verif_opts.index(rem["verification_status"])
            )
            evidence = st.text_area("Evidence", rem.get("evidence") or "")
            justification = st.text_area("Justification", "")
            notes = st.text_area("Notes", rem.get("notes") or "")
            expiry = st.date_input(
                "Risk acceptance expiry (accepted only)",
                datetime.now(UTC).date() + timedelta(days=90),
            )
            if st.form_submit_button("Apply"):
                payload = {}
                if status != rem["status"]:
                    payload["status"] = status
                if verification != rem["verification_status"]:
                    payload["verification_status"] = verification
                if evidence and evidence != (rem.get("evidence") or ""):
                    payload["evidence"] = evidence
                if justification:
                    payload["justification"] = justification
                if notes != (rem.get("notes") or ""):
                    payload["notes"] = notes or None
                if status == "accepted":
                    payload["risk_acceptance_expires_at"] = datetime.combine(
                        expiry, time(), UTC
                    ).isoformat()
                if not payload:
                    st.info("Nothing changed.")
                elif call(api().patch, f"/remediations/{rem['id']}", payload):
                    st.success("Remediation updated (recorded in the audit trail).")


def page_imports() -> None:
    header("Import Reports", "Upload normalised CSV/JSON or a Nessus CSV export")
    with st.form("upload", clear_on_submit=True):
        file = st.file_uploader("Scan file (max 5 MB)", type=["csv", "json"])
        a, b = st.columns(2)
        source = a.selectbox("Format", ["normalized_csv", "normalized_json", "nessus_csv"])
        demo = b.checkbox("Demo mode (accept fictional CVE-DEMO ids, flag records as demo)")
        if st.form_submit_button("Import") and file is not None:
            job = call(
                api().upload, file.name, file.getvalue(), source, "demo" if demo else "production"
            )
            if job:
                st.success(
                    f"Import #{job['id']} completed: {job['imported']} new, "
                    f"{job['updated']} updated, {job['rejected']} rejected, "
                    f"{job['duplicates']} in-file duplicate(s)."
                )
                if job["errors"]:
                    st.dataframe(pd.DataFrame(job["errors"]), use_container_width=True)
    jobs = call(api().get_all, "/imports")
    if not jobs:
        st.info("No import yet.")
        return
    df = pd.DataFrame(jobs)
    st.dataframe(
        df[
            [
                "id",
                "timestamp",
                "filename",
                "source",
                "mode",
                "status",
                "total_rows",
                "imported",
                "updated",
                "rejected",
                "duplicates",
                "actor",
            ]
        ],
        hide_index=True,
        use_container_width=True,
    )
    choice = st.selectbox("Import detail", [f"#{j['id']} {j['filename']}" for j in jobs])
    job = jobs[[f"#{j['id']} {j['filename']}" for j in jobs].index(choice)]
    if job["warnings"]:
        for w in job["warnings"]:
            st.warning(w)
    if job["errors"]:
        st.dataframe(pd.DataFrame(job["errors"]), use_container_width=True)
    else:
        st.success("No rejected row.")
    st.caption(f"SHA-256: {job['file_sha256']}")


def page_audit() -> None:
    header("Audit Trail", "Append-only journal of significant changes")
    c1, c2, c3 = st.columns(3)
    entity = c1.selectbox(
        "Entity", ["", "finding", "remediation", "asset", "vulnerability", "import_job", "system"]
    )
    action = c2.text_input("Action (exact)")
    actor = c3.text_input("Actor (exact)")
    data = call(
        api().get, "/audit-events", entity_type=entity, action=action, actor=actor, page_size=500
    )
    if not data or not data["items"]:
        st.info("No audit event.")
        return
    st.caption(f"{data['total']} event(s), newest first (showing up to 500).")
    df = pd.DataFrame(data["items"])
    df["previous_value"] = df["previous_value"].astype(str)
    df["new_value"] = df["new_value"].astype(str)
    st.dataframe(df, hide_index=True, use_container_width=True)
    st.caption("X-Actor is a free-text label in demo mode, not an authenticated identity.")


def page_reporting() -> None:
    header("CISO (RSSI) Reporting", "PDF executive report and CSV/JSON exports")
    st.write(
        "Reports are generated by the API from the current database snapshot. "
        "Scope follows the sidebar data filter (demo data included or not)."
    )
    cols = st.columns(3)
    for col, fmt, mime in [
        (cols[0], "pdf", "application/pdf"),
        (cols[1], "csv", "text/csv"),
        (cols[2], "json", "application/json"),
    ]:
        if col.button(f"Generate {fmt.upper()}", use_container_width=True):
            content = call(api().download, fmt, include_demo())
            if content:
                stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
                col.download_button(
                    f"Download {fmt.upper()}",
                    content,
                    file_name=f"cr360-report-{stamp}.{fmt}",
                    mime=mime,
                    use_container_width=True,
                )
    st.markdown("""
**PDF sections:** executive summary · inventory & coverage · top risks · remediation priorities,
owners and due dates · overdue items · risk evolution · limitations & data quality ·
technical appendix (findings and import history).
""")


def page_about() -> None:
    header("About / Architecture", "How CyberRemediate 360 is built")
    health = call(api().get, "/health")
    if health:
        st.success(
            f"API {health['version']} - environment **{health['environment']}** - "
            f"database **{health['database']}** - write access: "
            f"**{health['write_auth']}**"
        )
    st.markdown("""
```
CSV / JSON / Nessus CSV --> FastAPI /api/v1/imports --> Pydantic validation
                                                            |
                                                            v
Streamlit UI <-- REST JSON <-- API routes <-- services <-- SQLAlchemy UPSERT --> SQLite
                                                |
                                                +--> scoring 0-100, audit trail, reports
```
* **Backend:** FastAPI, Pydantic v2, SQLAlchemy 2.x, Alembic, SQLite (PostgreSQL-ready ORM).
* **Frontend:** Streamlit + Plotly, data only through the REST API.
* **Scoring:** severity (CVSS, 50) + exposure (20) + business criticality (15) + threat
  (KEV/EPSS, 15, not double-counted). See `docs/risk_scoring.md`.
* **Workflow:** open → in_progress → mitigated → resolved / accepted / false_positive with
  enforced rules and audit trail.
* **Security posture (demo):** localhost binding, restrictive CORS, optional API key for writes,
  upload size/type limits, CSV-injection-safe exports. Not production authentication.
""")
    cfg = call(api().get, "/config/scoring")
    if cfg:
        with st.expander("Active scoring weights and SLA"):
            st.json(cfg)


PAGES = {
    "Overview": page_overview,
    "Asset Inventory": page_assets,
    "Vulnerability Explorer": page_vulnerabilities,
    "Risk Prioritization": page_risk,
    "Remediation Tracker": page_remediation,
    "Import Reports": page_imports,
    "Audit Trail": page_audit,
    "RSSI Reporting": page_reporting,
    "About / Architecture": page_about,
}

with st.sidebar:
    st.markdown(
        f"<h2 style='color:{ACCENT};margin-bottom:0'>CyberRemediate 360</h2>"
        "<small>Vulnerability & Cyber Risk Management</small>",
        unsafe_allow_html=True,
    )
    selection = st.radio("Navigation", list(PAGES), label_visibility="collapsed")
    st.divider()
    st.selectbox(
        "Data scope", ["All data", "Real imports only", "Demo data only"], key="data_scope"
    )
    st.text_input(
        "Actor label (audit)",
        value="dashboard-user",
        key="actor",
        help="Recorded in the audit trail. Not an authenticated identity.",
    )
    st.caption(f"API: {ApiClient().base_url}")

PAGES[selection]()
