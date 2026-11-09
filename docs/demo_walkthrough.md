# Demo walkthrough (< 5 minutes)

## Fictional scenario: *Helios Logistics*

Helios Logistics (fictional) runs an e-commerce front end, an API gateway, a VPN appliance, an ERP database, an HR portal, a CI server, printers and a mail relay. A weekly scan (demo data) reports 14 findings; a JSON export from another tool adds 2; a Nessus export (synthetic) adds 3 real CVE identifiers on unknown hosts. The original 4 prototype findings (`AST-001..004`) are kept.

| Asset | Exposure / criticality | Finding | Priority | Remediation story |
|---|---|---|---|---|
| vpn-01 | internet / critical | CVE-DEMO-016 (9.1, demo KEV) | P1 95.5 | Plan created, **overdue** (detected 31 Aug, SLA 7 days) |
| shop-front-01 | internet / critical | CVE-DEMO-010 (9.8, demo KEV) | P1 99 | In progress (change request) |
| api-gw-01 | internet / high | CVE-DEMO-012 on 2 ports | P1 79 ×2 | Port 8443 **mitigated** by WAF rule; port 9443 still open |
| erp-db-01 | internal / critical | CVE-DEMO-013 (8.8) | P2 67 | **Resolved** with evidence, verification **verified** |
| lab-01 | isolated / low | CVE-DEMO-010 (same 9.8) | P2 64 | Same CVE, lower priority → explains contextual scoring |
| printer-01 | internal / low | CVE-DEMO-018 | P3 | **Risk accepted** for 90 days with justification |
| mail-01 | internet / high | CVE-DEMO-019 | P3 | **False positive** with justification |
| backup-01 | isolated / critical | CVE-DEMO-020 (no CVSS yet) | P4 | Scored with missing input → data-quality flag |

## Setup (once)

```powershell
cd D:\CyberRemediate360
.\.venv\Scripts\Activate.ps1
python scripts\seed_demo.py          # migrate + load the scenario (idempotent)
```

Terminal 1 – API:

```powershell
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Terminal 2 – dashboard:

```powershell
streamlit run frontend\app.py
```

## Script

1. **0:00 – Overview** (http://127.0.0.1:8501): KPIs come from `GET /dashboard/summary`; point out the demo banner and the *Data scope* selector (demo vs real imports). Show 3 overdue remediations, severity donut, top-10 assets, weekly trend.
2. **0:45 – Import Reports**: upload `data/samples/invalid_examples.csv` with *Demo mode* ticked. Result: 1 new, 5 rejected, 1 duplicate; show per-line reasons (CVSS 15.0, IP 999.1.1.1, malformed CVE, missing hostname, bad enums). Re-upload the same file → 0 new, 1 updated (idempotent).
3. **1:30 – Risk Prioritization**: pick CVE-DEMO-010 on shop-front-01 (99, P1) then on lab-01 (64, P2): same CVSS, different exposure/criticality. The bar chart and the reasons list show each component.
4. **2:15 – Asset Inventory**: open `NES-192.0.2.150` (Log4Shell, CVSS 10 but P3 because exposure/criticality are unknown). Set exposure *internet* / criticality *high* → findings re-scored to P1 → this is recorded in the audit trail.
5. **3:00 – Remediation Tracker**: select the vpn-01 plan (overdue). Try *resolved* without evidence → rejected with a clear rule. Add evidence → resolved, verification pending.
6. **3:40 – Audit Trail**: filter `remediation` → previous/new values, actor label.
7. **4:10 – RSSI Reporting**: generate the PDF (executive summary, top risks, owners, overdue, trend, limitations, appendix) and the CSV.
8. **4:40 – Swagger** (http://127.0.0.1:8000/docs): show versioned endpoints and the error envelope.

Reset the demo at any time: stop the API, delete `data\cyberremediate.db` (a backup is in `data\backups\`), run `python scripts\seed_demo.py`.
