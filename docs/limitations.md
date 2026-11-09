# Limitations

Known, deliberate or not-yet-addressed limitations. Nothing here is hidden behind a claim elsewhere.

## Security

* Access control is a single optional shared API key for writes; reads are unauthenticated. No users, roles, SSO or rate limiting. **Not production authentication.**
* `X-Actor` is an unauthenticated label; the audit trail can be attributed to any name by a client.
* The audit table is append-only by API design only; nothing prevents direct database edits (no hash chaining).
* No TLS: the services bind to `127.0.0.1` and are meant for local use.

## Data & scoring

* EPSS and KEV are **not fetched**; they are used only when an import provides them with a `threat_source`. Demo signals are labelled `demo-simulated` and are fictional.
* The priority score is an internal ranking heuristic, not a calibrated probability; weights are expert choices documented in `risk_scoring.md`, not statistically fitted.
* Unknown exposure/criticality score 0 (flagged); this can under-rank findings until the inventory is completed.
* CVSS vectors are format-validated but the base score is not recomputed from the vector.
* One remediation plan per finding; history is in the audit trail rather than in multiple plans.
* Trends are weekly counts of recorded `first_seen`/`completed_at`/import dates; there is no historical snapshot of the backlog (reopened items are not replayed).
* Nessus support covers the CSV export layout only (not `.nessus` XML) and was tested against a synthetic sample, not a real scanner export.

## Engineering

* Dashboard aggregations load findings in Python — fine for thousands of rows, not for millions (would move to SQL GROUP BY).
* Imports are synchronous within the HTTP request (limit 5 MB / 50 000 rows).
* PostgreSQL is supported in principle by the ORM but **not tested**; no Docker/Compose files are shipped because they could not be tested on the development machine.
* Streamlit UI is covered by manual verification (all pages loaded without error against the live API), not by automated UI tests.
* The PDF report content is tested (generated, valid PDF header, values shared with JSON/CSV), but its visual layout was not reviewed with an automated renderer.
* Downgrade of migration `0002` is not supported; restore from `data/backups/` instead.
