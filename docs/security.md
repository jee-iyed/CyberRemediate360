# Security

This is a **portfolio / demonstration** application. The controls below are real and tested, but the access control is **not** production-grade authentication.

## Demo mode vs. secure production

| Topic | Implemented here (demo) | Required for production |
|---|---|---|
| Authentication | Optional shared `X-API-Key` for write endpoints (constant-time comparison). Reads are open. | OIDC/SAML SSO, per-user identities, short-lived tokens |
| Authorisation | None beyond "can write / cannot write" | RBAC (analyst, owner, approver, auditor), segregation of duties for risk acceptance |
| Actor in audit trail | `X-Actor` free-text label, sanitised (64 chars, safe charset) | Derived from the authenticated identity |
| Fail-closed | `CR360_APP_ENV=production` without a key → writes return 503 | Same, plus secrets from a vault |
| Network | Binds to `127.0.0.1`; CORS limited to the Streamlit origin | TLS reverse proxy, WAF, rate limiting |
| Audit trail | Append-only by API design (no update/delete endpoint) | Tamper-evident storage (hash chaining / WORM), log forwarding to a SIEM |
| Database | SQLite file, gitignored | Managed PostgreSQL, encryption at rest, backups |

A static API key in a `.env` file is a convenience for a single local client. It must not be presented as production security.

## Controls implemented

* **Input validation** – Pydantic v2 everywhere; write bodies use `extra="forbid"`; controlled vocabularies; CHECK constraints in SQL as a second line of defence.
* **SQL injection** – ORM expressions with bound parameters only; sort fields mapped through allow-lists; `LIKE` wildcards escaped (`tests/test_security_and_reporting.py`).
* **Uploads** – size limit enforced while reading (`max_upload_bytes + 1`), row limit, extension must match the declared source, NUL bytes rejected (binary), filename reduced to a safe basename (no path traversal), file never written to disk, SHA-256 recorded.
* **No execution of imported data** – CSV/JSON parsed as data; no `eval`, no shell, no paths opened from file content.
* **CSV formula injection** – exported cells starting with `= + - @ \t \r` are prefixed with `'`.
* **HTTP headers** – `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
* **Errors** – consistent JSON error envelope; no stack traces returned.
* **Secrets** – none in the repository; `.env` gitignored; `.env.example` contains placeholders only; health endpoint reports the auth *mode*, never the key.
* **Transactions** – imports are atomic; workflow changes and their audit events are committed together.

## Data handling

* Demo data uses fictional `CVE-DEMO-*` ids, fictional company names and RFC 5737 / RFC 3849 documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). Records imported in demo mode are flagged `is_demo` and can be excluded from dashboards and reports.
* The Nessus sample is synthetic (fictional hosts) and references real public CVE identifiers only.
* The platform performs **no scanning**, no network enrichment and no outbound calls; it runs fully offline.

## Repository hygiene

`.gitignore` excludes `.venv/`, `*.db`, `data/backups/`, `.env*` (except the example), keys/certificates, caches, logs and generated reports. Before publishing, tracked files are checked for secrets (see the final verification report in the README).

## Reporting a vulnerability

Open a private security advisory on the GitHub repository rather than a public issue.
