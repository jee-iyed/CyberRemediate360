import pytest

from app.core.config import ScoringConfig
from app.services.scoring import RiskInput, compute_risk


def score(cvss, exposure="internal", crit="medium", kev=None, epss=None):
    return compute_risk(RiskInput(cvss, exposure, crit, kev, epss))


def test_documented_examples():
    # Values documented in docs/risk_scoring.md
    assert score(9.8, "internet", "critical").score == 84.0
    assert score(9.8, "internet", "critical").priority == "P1"
    assert score(8.1, "internal", "critical").score == 63.5
    assert score(7.5, "isolated", "low").score == 37.5
    assert score(6.5, "internet", "high").score == 62.5


def test_bounds_min_and_max():
    assert score(0.0, "isolated", "low", kev=False, epss=0.0).score == 0.0
    top = score(10.0, "internet", "critical", kev=True, epss=0.99)
    assert top.score == 100.0
    assert top.priority == "P1"


def test_same_cvss_different_priority_due_to_context():
    exposed = score(9.8, "internet", "critical")
    lab = score(9.8, "isolated", "low")
    assert exposed.score > lab.score
    assert exposed.priority == "P1" and lab.priority == "P3"


def test_ordering_is_monotonic():
    ordered = [score(c, "internal", "high").score for c in (2.0, 5.0, 7.0, 9.0)]
    assert ordered == sorted(ordered)
    assert score(7, "internet").score > score(7, "internal").score > score(7, "isolated").score


def test_threat_signals_not_double_counted():
    both = score(5.0, kev=True, epss=0.9)
    kev_only = score(5.0, kev=True, epss=None)
    assert both.components["threat"] == kev_only.components["threat"] == 15
    assert any("no double count" in r for r in both.reasons)


def test_epss_thresholds():
    assert score(5.0, epss=0.05).components["threat"] == 0
    assert score(5.0, epss=0.1).components["threat"] == 5
    assert score(5.0, epss=0.5).components["threat"] == 10


def test_missing_data_is_not_invented():
    result = score(None, "unknown", "unknown")
    assert result.score == 0
    assert {"cvss_score", "exposure", "business_criticality"} <= set(result.missing_inputs)
    assert result.cvss_severity == "unknown"


def test_priority_thresholds_and_config():
    cfg = ScoringConfig(p1_threshold=90)
    assert compute_risk(RiskInput(9.8, "internet", "critical"), cfg).priority == "P2"


@pytest.mark.parametrize("bad", [-0.1, 10.1])
def test_invalid_cvss_rejected(bad):
    with pytest.raises(ValueError):
        score(bad)


def test_deterministic():
    assert score(7.3, "internet", "high", True, 0.2) == score(7.3, "internet", "high", True, 0.2)
