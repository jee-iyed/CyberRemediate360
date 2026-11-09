# Technical decisions (ADR-style)

| # | Decision | Alternatives considered | Rationale |
|---|---|---|---|
| 1 | **Modular monolith** (FastAPI + services + SQLite) | Microservices, Celery/Redis workers | Single-laptop, offline demo; the previous Docker-based SIEM crashed the dev machine. Clear module boundaries keep later extraction possible. |
| 2 | **SQLite** as default database | PostgreSQL in Docker | Zero infrastructure; foreign keys enforced via PRAGMA; ORM keeps PostgreSQL an option (untested). |
| 3 | **SQLAlchemy 2.x + Alembic** | Raw `sqlite3` (legacy prototype) | Typed models, bound parameters, real migrations: the legacy DB was migrated in place with a pre-migration backup. |
| 4 | **Surrogate integer PKs + unique business keys** | Keep text PKs (`AST-001`, CVE id) | Business identifiers can change format; integer FKs are smaller and stable; uniqueness still enforced on `asset_key`/`cve_id`. |
| 5 | **Finding key = asset + CVE + location** | asset + CVE only (legacy) | Same CVE on several ports is distinct work; legacy rows migrated with empty location. |
| 6 | **Pydantic v2 row model** for import validation | Hand-written checks (legacy `validate_csv.py`) | Field-level messages, reuse of type coercion, context-aware (demo vs production mode). Legacy rules kept and extended (IP, CVE, CVSS range, enums). |
| 7 | **All-or-nothing transaction per import**, invalid rows rejected individually | Per-row savepoints (legacy) | Valid rows are already filtered before writing; a DB error then indicates a systemic problem, so nothing partial is committed. |
| 8 | **Additive capped scoring** | Multiplicative (CVSS × exposure factor), ML model | Explainable, linear, easy to test at boundaries; avoids opaque results; threat signals combined with `max`. |
| 9 | **Workflow on the remediation, mirrored on the finding** | Separate status machines | One source of truth for transitions; finding status always reflects the plan; history in audit events. |
| 10 | **Explicit demo mode** (`CVE-DEMO-*`, `is_demo`) | Accept anything | Prevents fictional data from polluting real metrics; filters in API, UI and reports. |
| 11 | **ReportLab** for PDF | WeasyPrint (needs GTK on Windows), FPDF | Pure Python, maintained, works on Windows without system libraries. |
| 12 | **Streamlit consumes the API only** | Streamlit reading SQLite directly | Single validation/audit path; demonstrates API design; UI replaceable. |
| 13 | **Shared API key, documented as demo-grade** | Fake login page | A fake login would suggest security that does not exist; the key is honest and fail-closed in production mode. |
| 14 | **Pinned versions** (`requirements*.txt`) + `requirements-lock.txt` (pip freeze) | Unpinned | Reproducible installs on Python 3.11. |
| 15 | **No Docker artefacts shipped** | Untested Compose file | Only tested deployment paths are documented. |
