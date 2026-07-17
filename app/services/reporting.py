from collections import Counter

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 2}


def calculate_risk_score(severities: list[str]) -> float:
    return float(min(100, sum(SEVERITY_WEIGHTS.get(item, 0) for item in severities)))


def severity_summary(severities: list[str]) -> dict[str, int]:
    counts = Counter(severities)
    return {name: counts.get(name, 0) for name in ("critical", "high", "medium", "low")}
