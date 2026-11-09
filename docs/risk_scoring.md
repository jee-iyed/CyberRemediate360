# Risk scoring & prioritisation

CyberRemediate 360 stores **three separate things** for every finding:

| Data | Where | Meaning |
|---|---|---|
| CVSS base score, version, vector | `vulnerabilities.cvss_score / cvss_version / cvss_vector` | Intrinsic technical severity published for the CVE. Stored as a `REAL`, never as text. |
| Threat signals (CISA KEV, EPSS) | `vulnerabilities.kev / epss_score / threat_source` | Only stored when the import provides them **with a documented source** (`threat_source` is mandatory). The platform never fetches or guesses them. |
| Internal priority score + justification | `findings.risk_score / priority / risk_explanation` | Ranking aid for remediation work, 0–100, computed by `backend/app/services/scoring.py`. |

> The internal score is **not** a probability of compromise and is not a replacement for CVSS. It answers one question: *which findings should the team fix first?*

## Model `cr360-additive-v1`

```
score = severity + exposure + business_criticality + threat      (clamped to 0..100)
```

| Component | Rule | Max |
|---|---|---|
| Severity | `CVSS base / 10 × 50` | 50 |
| Exposure of the asset | internet 20 · internal 8 · isolated 0 · unknown 0 (+ flagged) | 20 |
| Business criticality | critical 15 · high 10 · medium 5 · low 0 · unknown 0 (+ flagged) | 15 |
| Threat | `max(KEV 15, EPSS ≥ 0.5 → 10, EPSS ≥ 0.1 → 5)`, capped at 15 | 15 |

Priority bands: **P1 ≥ 75**, **P2 ≥ 55**, **P3 ≥ 35**, **P4 < 35**. Default SLA: P1 7 days, P2 30, P3 90, P4 180 (clock starts at `first_seen`).

All weights, thresholds and SLAs are configurable through environment variables (`CR360_SCORING__EXPOSURE_INTERNET=20`, `CR360_SLA__P1_DAYS=7`, …) and exposed at `GET /api/v1/config/scoring`.

### Why these weights

* **Severity carries half of the score**: CVSS remains the primary technical signal and keeps the ranking explainable to auditors.
* **Exposure (20) > criticality (15)**: an internet-facing service is reachable by any attacker; criticality describes impact, which CVSS already partly covers (C/I/A metrics).
* **Threat is capped and uses `max`, not a sum**: KEV ("exploited in the wild") and EPSS ("likely to be exploited") measure the same dimension — adding both would double count.
* **CVSS environmental/temporal metrics are not used**: exposure and criticality would otherwise be counted twice (once in an environmental CVSS, once here).

### Missing data

Missing inputs contribute **0** and are listed in `risk_explanation.missing_inputs`; nothing is invented. The dashboard counts "findings scored with missing inputs" so the data-quality gap is visible. Consequence to keep in mind: a CVSS 10.0 finding on an asset with unknown exposure/criticality scores only 50 (P3) — the fix is to complete the inventory (e.g. `PATCH /api/v1/assets/{id}`), which re-scores automatically.

## Worked examples (verified by `tests/test_scoring.py`)

| Finding | CVSS | Exposure | Criticality | Threat | Calculation | Score | Priority |
|---|---|---|---|---|---|---|---|
| CVE-DEMO-001 on web-server-01 | 9.8 | internet | critical | – | 49 + 20 + 15 + 0 | **84.0** | P1 |
| CVE-DEMO-002 on db-server-01 | 8.1 | internal | critical | – | 40.5 + 8 + 15 | **63.5** | P2 |
| CVE-DEMO-004 on app-server-01 | 6.5 | internet | high | – | 32.5 + 20 + 10 | **62.5** | P2 |
| CVE-DEMO-003 on test-server-01 | 7.5 | isolated | low | – | 37.5 + 0 + 0 | **37.5** | P3 |
| CVE-DEMO-010 on HLX-WEB-01 (demo KEV) | 9.8 | internet | critical | KEV 15 | 49 + 20 + 15 + 15 | **99.0** | P1 |
| CVE-DEMO-010 on HLX-LAB-01 (demo KEV) | 9.8 | isolated | low | KEV 15 | 49 + 0 + 0 + 15 | **64.0** | P2 |

### Why two findings with the same CVSS get different priorities

CVE-DEMO-010 has the same CVSS 9.8 on both hosts. On `HLX-WEB-01` the asset is internet-facing and business-critical (99 → P1); on the isolated lab host `HLX-LAB-01` nobody outside can reach it and nothing critical runs there (64 → P2). CVSS describes the **vulnerability**; the priority describes the **risk in this organisation's context**. Conversely, CVE-DEMO-004 (CVSS 6.5, internet, high) ranks above CVE-DEMO-003 (CVSS 7.5, isolated, low).

## Workflow states (remediation)

| State | Meaning | Required |
|---|---|---|
| `open` | Detected, not yet handled | – |
| `in_progress` | Work started | – |
| `mitigated` | Compensating control (WAF rule, isolation). Root cause still present, SLA keeps running | justification |
| `resolved` | Root cause fixed (patch, config) | evidence; verification → `pending` |
| `accepted` | Risk formally accepted by an owner | justification + expiry ≤ 365 days |
| `false_positive` | Proven not applicable | justification |

Re-opening a closed item requires a justification. A `resolved` finding observed again by a later scan is re-opened automatically with verification `failed` (regression). A finding **absent** from a scan is never closed automatically.
