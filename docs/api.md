# REST API (v1)

Interactive documentation: **http://127.0.0.1:8000/docs** (Swagger UI) and `/redoc`; schema at `/openapi.json`.

All list endpoints return:

```json
{"items": [...], "total": 23, "page": 1, "page_size": 50}
```

Query parameters common to list endpoints: `page` (≥1), `page_size` (1–500), `sort` (field name, `-` prefix for descending; only allow-listed fields). Errors always use:

```json
{"error": {"code": "invalid_transition", "message": "Resolving requires evidence of the fix", "details": null}}
```

| Code | HTTP |
|---|---|
| `validation_error` | 422 – request body / query failed Pydantic validation |
| `import_rejected` | 422 – file rejected (details include `import_job_id`) |
| `invalid_transition` | 422 – workflow rule violated |
| `not_found` | 404 |
| `conflict` | 409 – duplicate business key |
| `payload_too_large` | 413 |
| `http_error` | 401 missing/invalid API key, 503 writes disabled |

## Endpoints

| Method | Path | Description | Write auth |
|---|---|---|---|
| GET | `/api/v1/health` | Liveness, DB status, auth mode | |
| GET | `/api/v1/config/scoring` | Active weights and SLA | |
| GET | `/api/v1/assets` | Filters: `q`, `exposure`, `criticality`, `environment`, `is_demo`; sort: `id, asset_key, hostname, business_criticality, exposure, created_at` | |
| POST | `/api/v1/assets` | Create asset (409 if `asset_key` exists) | ✔ |
| GET | `/api/v1/assets/{id}` | Asset with its findings | |
| PATCH | `/api/v1/assets/{id}` | Update owner / environment / exposure / criticality → findings re-scored | ✔ |
| GET | `/api/v1/vulnerabilities` | Filters: `q`, `min_cvss`, `kev`, `is_demo` | |
| GET | `/api/v1/findings` | Filters: `q`, `status` (multi), `priority` (multi), `asset_id`, `min_risk`, `min_cvss`, `exposure`, `is_demo`; default sort risk desc | |
| GET | `/api/v1/findings/{id}` | Finding + asset + vulnerability + remediation + `risk_explanation` | |
| POST | `/api/v1/imports` | Multipart: `file`, `source` (`normalized_csv`, `normalized_json`, `nessus_csv`), `mode` (`production`, `demo`) | ✔ |
| GET | `/api/v1/imports`, `/api/v1/imports/{id}` | Import jobs with per-line errors | |
| GET | `/api/v1/dashboard/summary` | KPIs (`include_demo=false` to exclude fictional data) | |
| GET | `/api/v1/dashboard/trends` | Weekly new/closed findings and imports | |
| GET | `/api/v1/remediations` | Filters: `status`, `owner`, `overdue=true` | |
| GET | `/api/v1/remediations/{id}` | | |
| POST | `/api/v1/remediations` | Create plan (due date defaults to SLA) | ✔ |
| PATCH | `/api/v1/remediations/{id}` | Update fields / workflow transition | ✔ |
| GET | `/api/v1/audit-events` | Filters: `entity_type`, `entity_id`, `action`, `actor` | |
| GET | `/api/v1/reports/export` | `format=pdf|csv|json`, `include_demo` | |

"Write auth" = requires `X-API-Key` when `CR360_API_KEY` is set (see [security.md](security.md)). `X-Actor` sets the audit label.

## Examples (PowerShell)

```powershell
$api = "http://127.0.0.1:8000/api/v1"
Invoke-RestMethod "$api/health"
Invoke-RestMethod "$api/findings?priority=P1&sort=-risk_score"
# Import (curl.exe ships with Windows 10/11)
curl.exe -F "file=@data/samples/demo_scenario.csv" -F "source=normalized_csv" -F "mode=demo" "$api/imports"
# Create and resolve a remediation
$r = Invoke-RestMethod "$api/remediations" -Method Post -ContentType "application/json" `
      -Body '{"finding_id": 3, "owner": "Ops", "action": "Apply patch"}'
Invoke-RestMethod "$api/remediations/$($r.id)" -Method Patch -ContentType "application/json" `
      -Body '{"status": "resolved", "evidence": "Rescan 2026-11-09 clean"}'
Invoke-WebRequest "$api/reports/export?format=pdf" -OutFile reports/report.pdf
```

## Import formats

### Normalised CSV / JSON

Required columns: `asset_id`, `hostname`, `ip_address`, `cve_id`. Optional: `cvss_score`, `cvss_version` (2.0/3.0/3.1/4.0), `cvss_vector`, `title`, `description`, `cwe_id`, `references` (URLs separated by `;` or a JSON list), `exposure`, `business_criticality`, `owner`, `environment`, `status` (`open`/`in_progress` only), `scanner_source`, `service`, `port`, `protocol`, `first_seen`, `last_seen` (ISO 8601, UTC assumed if naive), `evidence`, `epss_score`, `kev`, `threat_source` (required when `kev`/`epss_score` given).

CSV delimiter `,` `;` or tab, UTF-8 (BOM accepted; Windows-1252 fallback with a warning). JSON: a list of objects or `{"findings": [...]}`; nested objects are rejected. Limits: 5 MB (`CR360_MAX_UPLOAD_BYTES`), 50 000 rows (`CR360_MAX_IMPORT_ROWS`), extension must match the source.

Validation: IPv4/IPv6 via `ipaddress`, CVE `^CVE-\d{4}-\d{4,7}$` (`CVE-DEMO-NNN` only in demo mode), CVSS finite number 0–10 (`9,8` accepted), port 0–65535, RFC 1123 hostname, controlled vocabularies, `last_seen ≥ first_seen`, no future dates.

### Nessus CSV adapter

Maps the column layout of a Tenable Nessus "CSV" export (`Plugin ID, CVE, CVSS v2.0 Base Score, CVSS v3.0 Base Score, Risk, Host, Protocol, Port, Name, Synopsis, Description, Solution, See Also, Plugin Output`). Rows without a CVE (informational plugins) are rejected with an explicit reason. Asset keys are `NES-<ip>`; exposure/criticality are not in scanner output, so existing inventory values are kept. `data/samples/nessus_export_sample.csv` is a **synthetic** file written for this project reproducing that layout (fictional hosts, real public CVE identifiers with their NVD base scores).
