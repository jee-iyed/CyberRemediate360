# Interview explanation / Explication pour entretien

## Pitch (EN)

CyberRemediate 360 turns raw scanner output into a prioritised, tracked remediation programme. It validates and normalises CSV/JSON/Nessus exports, stores them in a relational model with business keys and idempotent UPSERTs, ranks findings with an explainable 0–100 score that combines CVSS with asset context and verified threat signals, enforces a remediation workflow with evidence and justifications, keeps an audit trail and produces a CISO report — all offline on SQLite, FastAPI and Streamlit, with 80+ automated tests and CI.

## Pitch (FR)

CyberRemediate 360 transforme des résultats de scanners en programme de remédiation priorisé et suivi. La plateforme valide et normalise des exports CSV/JSON/Nessus, les stocke dans un modèle relationnel avec clés métier et UPSERT idempotent, classe les findings avec un score explicable de 0 à 100 combinant CVSS, contexte de l'actif et signaux de menace vérifiés, impose un workflow de remédiation avec preuves et justifications, journalise les changements et produit un rapport RSSI — entièrement hors ligne avec SQLite, FastAPI et Streamlit, plus de 80 tests automatisés et une CI.

## Concepts

| Concept | English | Français |
|---|---|---|
| **CVE** | *Common Vulnerabilities and Exposures*: a unique public identifier for a known vulnerability (`CVE-2021-44228`), assigned by a CNA, catalogued by MITRE/NVD. It identifies, it does not score. | Identifiant public unique d'une vulnérabilité connue. Il identifie la faille, il ne mesure pas sa gravité. |
| **CWE** | *Common Weakness Enumeration*: the class of software weakness behind a CVE (`CWE-89` SQL injection). Useful for root-cause and secure-coding trends. | Catégorie de faiblesse logicielle à l'origine d'une CVE (ex. CWE-89 injection SQL). Utile pour l'analyse des causes racines. |
| **CVSS** | *Common Vulnerability Scoring System* (FIRST): 0–10 base score + vector describing exploitability and impact. Measures **technical severity**, not risk in my context. Versions 2.0, 3.x, 4.0 are not directly comparable, so the version is stored. | Score de 0 à 10 et vecteur décrivant exploitabilité et impact. Mesure la **sévérité technique**, pas le risque dans mon contexte. La version est conservée car 2.0/3.x/4.0 ne sont pas comparables. |
| **EPSS** | *Exploit Prediction Scoring System* (FIRST): daily probability (0–1) that a CVE will be exploited in the next 30 days. | Probabilité (0–1) qu'une CVE soit exploitée dans les 30 prochains jours, publiée quotidiennement par FIRST. |
| **KEV** | CISA *Known Exploited Vulnerabilities* catalogue: CVEs with evidence of exploitation in the wild. | Catalogue CISA des vulnérabilités dont l'exploitation active est avérée. |
| **ORM** | Object-Relational Mapper (SQLAlchemy): Python classes mapped to tables; queries built as expressions with bound parameters → portability and protection against SQL injection. | Correspondance objets ↔ tables ; requêtes paramétrées, portabilité (SQLite → PostgreSQL), protection contre l'injection SQL. |
| **REST** | Resource-oriented HTTP API: nouns in URLs (`/findings/3`), verbs as HTTP methods (GET/POST/PATCH), status codes, stateless, JSON. Versioned under `/api/v1`. | API HTTP orientée ressources, méthodes HTTP, codes de statut, sans état, versionnée. |
| **JOIN** | SQL operation combining rows of related tables via keys, e.g. findings ⋈ assets ⋈ vulnerabilities to search by hostname or CVE. | Combinaison de lignes de tables liées par leurs clés (findings + assets + vulnerabilities). |
| **Idempotence** | Running the same operation twice gives the same state as running it once. Re-importing the same scan creates 0 new rows. | Rejouer une opération ne change pas le résultat : réimporter un scan ne crée aucun doublon. |
| **UPSERT** | "Update or insert" keyed on a business key: insert if absent, update if present. Here: asset by `asset_key`, CVE by `cve_id`, finding by (asset, CVE, location). | Insertion ou mise à jour selon la clé métier. |
| **Residual risk** | Risk remaining after controls: a *mitigated* finding (WAF rule) still carries residual risk because the root cause exists; an *accepted* risk is residual risk formally owned for a limited time. | Risque restant après traitement : une mitigation réduit le risque sans supprimer la cause ; l'acceptation formalise un risque résiduel, limitée dans le temps. |
| **Remediation** | Eliminating the root cause (patch, configuration change), proven by evidence and ideally verified by a rescan. Distinct from mitigation, acceptance and false positive. | Suppression de la cause racine, prouvée et vérifiée ; distincte de la mitigation, de l'acceptation et du faux positif. |

## Design choices to defend / Choix de conception

1. **Separate CVSS from the internal priority** – CVSS is an external, standard fact; the priority is my organisation's decision. Mixing them would lose traceability. / *Le CVSS est un fait externe ; la priorité est une décision interne.*
2. **Additive, capped model instead of a black box** – every point can be explained to an auditor; KEV and EPSS are `max`-combined to avoid double counting; missing data scores 0 and is flagged, never invented.
3. **Business key with location** – the same CVE on two ports must be fixed and verified twice; the same row re-scanned is not a new finding.
4. **Never auto-close on absence** – a host can be absent from a scan because it was offline or out of scope. Closure needs evidence; reappearance after resolution re-opens (regression).
5. **One transaction per import** – no half-imported file; failed imports still leave an `ImportJob` record for traceability.
6. **SQLite + Alembic** – zero infrastructure for a laptop demo, real migrations (the legacy prototype DB was migrated without loss), ORM keeps PostgreSQL possible.
7. **Streamlit reads only through the API** – same validation and audit for UI and scripts; the UI is replaceable.
8. **Honest security** – API key is labelled as demo-grade; production needs SSO/RBAC (see security.md).

## Likely questions / Questions probables

* *Why is a CVSS 10 (Log4Shell) only P3 in the demo?* Because the Nessus host has unknown exposure and criticality: the model refuses to guess and flags the data gap. Completing the inventory makes it P1 — this shows why asset management is part of vulnerability management.
* *How would you add EPSS/KEV automatically?* A scheduled, offline-capable enrichment job downloading the official KEV JSON and EPSS CSV, storing `threat_source` with date, then re-scoring. Kept out of scope to stay offline and avoid unverified data.
* *How do you prevent SQL injection?* ORM bound parameters, sort allow-lists, escaped LIKE wildcards, tested.
* *What breaks at scale?* SQLite write concurrency and in-memory dashboard aggregation; next step is PostgreSQL + SQL aggregations + background import jobs.
* *How is the audit trail protected?* Append-only by API; in production it should be forwarded to a SIEM / WORM storage and signed.
