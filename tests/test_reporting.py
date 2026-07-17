from app.services.reporting import calculate_risk_score, severity_summary


def test_risk_score_is_bounded() -> None:
    assert calculate_risk_score(["critical"] * 10) == 100
    assert calculate_risk_score(["high", "medium", "low"]) == 24


def test_severity_summary() -> None:
    assert severity_summary(["high", "high", "low"]) == {
        "critical": 0,
        "high": 2,
        "medium": 0,
        "low": 1,
    }
