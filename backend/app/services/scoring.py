"""Internal priority score (0-100): deterministic, explainable, configurable.

This score ranks remediation work. It is NOT a probability of compromise and it does not
replace CVSS (which is stored unchanged next to it).

    score = severity + exposure + business_criticality + threat

* severity    = CVSS base score / 10 * severity_max (50)      -> intrinsic technical severity
* exposure    = internet 20 / internal 8 / isolated 0           -> reachability of the asset
* criticality = critical 15 / high 10 / medium 5 / low 0        -> business impact
* threat      = max(KEV 15, EPSS>=0.5 10, EPSS>=0.1 5), capped at 15
                KEV and EPSS both describe exploitation likelihood, so they are NOT summed
                (avoids double counting).

Missing inputs contribute 0 and are listed in ``missing_inputs``: no value is invented.
CVSS environmental/temporal metrics are not used, so asset context is not counted twice.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from app.core.config import ScoringConfig
from app.core.domain import cvss_severity


@dataclass(frozen=True)
class RiskInput:
    cvss_score: float | None
    exposure: str | None
    business_criticality: str | None
    kev: bool | None = None
    epss_score: float | None = None


@dataclass(frozen=True)
class RiskResult:
    score: float
    priority: str
    components: dict[str, float]
    missing_inputs: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    cvss_severity: str = "unknown"
    model: str = "cr360-additive-v1"

    def to_dict(self) -> dict:
        return asdict(self)


def _priority(score: float, cfg: ScoringConfig) -> str:
    if score >= cfg.p1_threshold:
        return "P1"
    if score >= cfg.p2_threshold:
        return "P2"
    if score >= cfg.p3_threshold:
        return "P3"
    return "P4"


def compute_risk(data: RiskInput, cfg: ScoringConfig | None = None) -> RiskResult:
    cfg = cfg or ScoringConfig()
    missing: list[str] = []
    reasons: list[str] = []

    # 1. Severity (CVSS base score).
    if data.cvss_score is None:
        severity = 0.0
        missing.append("cvss_score")
        reasons.append("CVSS score unavailable: severity component set to 0 (needs triage)")
    else:
        if not 0 <= data.cvss_score <= 10:
            raise ValueError("cvss_score must be within 0-10")
        severity = data.cvss_score / 10 * cfg.severity_max
        reasons.append(
            f"CVSS {data.cvss_score:.1f} ({cvss_severity(data.cvss_score)}) "
            f"-> {severity:.1f}/{cfg.severity_max:.0f}"
        )

    # 2. Exposure.
    exposure_map = {
        "internet": cfg.exposure_internet,
        "internal": cfg.exposure_internal,
        "isolated": cfg.exposure_isolated,
    }
    exposure_key = (data.exposure or "unknown").lower()
    if exposure_key in exposure_map:
        exposure = exposure_map[exposure_key]
        reasons.append(f"Asset exposure '{exposure_key}' -> {exposure:.0f}")
    else:
        exposure = 0.0
        missing.append("exposure")
        reasons.append("Asset exposure unknown -> 0 (update the asset inventory)")

    # 3. Business criticality.
    criticality_map = {
        "critical": cfg.criticality_critical,
        "high": cfg.criticality_high,
        "medium": cfg.criticality_medium,
        "low": cfg.criticality_low,
    }
    criticality_key = (data.business_criticality or "unknown").lower()
    if criticality_key in criticality_map:
        criticality = criticality_map[criticality_key]
        reasons.append(f"Business criticality '{criticality_key}' -> {criticality:.0f}")
    else:
        criticality = 0.0
        missing.append("business_criticality")
        reasons.append("Business criticality unknown -> 0 (update the asset inventory)")

    # 4. Threat signals (only when a verified value is present).
    threat_candidates = [0.0]
    if data.kev is True:
        threat_candidates.append(cfg.threat_kev)
        reasons.append(f"Listed in CISA KEV -> {cfg.threat_kev:.0f}")
    elif data.kev is None:
        missing.append("kev")
    if data.epss_score is not None:
        if not 0 <= data.epss_score <= 1:
            raise ValueError("epss_score must be within 0-1")
        if data.epss_score >= cfg.epss_high_threshold:
            threat_candidates.append(cfg.threat_epss_high)
            reasons.append(
                f"EPSS {data.epss_score:.2f} >= {cfg.epss_high_threshold} -> "
                f"{cfg.threat_epss_high:.0f}"
            )
        elif data.epss_score >= cfg.epss_medium_threshold:
            threat_candidates.append(cfg.threat_epss_medium)
            reasons.append(
                f"EPSS {data.epss_score:.2f} >= {cfg.epss_medium_threshold} -> "
                f"{cfg.threat_epss_medium:.0f}"
            )
    else:
        missing.append("epss_score")
    threat = min(max(threat_candidates), cfg.threat_max)
    if threat and len(threat_candidates) > 2:
        reasons.append("KEV and EPSS overlap: highest threat signal kept (no double count)")

    score = round(min(100.0, max(0.0, severity + exposure + criticality + threat)), 1)
    priority = _priority(score, cfg)
    reasons.append(f"Total {score} -> priority {priority}")
    return RiskResult(
        score=score,
        priority=priority,
        components={
            "severity": round(severity, 1),
            "exposure": round(exposure, 1),
            "business_criticality": round(criticality, 1),
            "threat": round(threat, 1),
        },
        missing_inputs=missing,
        reasons=reasons,
        cvss_severity=cvss_severity(data.cvss_score),
    )
