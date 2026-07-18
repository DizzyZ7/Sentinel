from types import SimpleNamespace

from app.services.sarif import build_sarif


def test_sarif_contains_only_confirmed_findings() -> None:
    confirmed = SimpleNamespace(
        confirmed=True,
        severity="high",
        rule_id="PY_SQL_INTERPOLATION",
        title="SQL injection",
        recommendation="Use parameters",
        static_rationale="Interpolated query",
        language="python",
        cwe="CWE-89",
        explanation="Request data reaches SQL text.",
        file_path="app.py",
        line=10,
        end_line=10,
        cvss_score=8.2,
        confidence=0.95,
        patch_valid=True,
        decision=SimpleNamespace(decision="approved"),
        verification=SimpleNamespace(status="passed", source_executed=False),
    )
    rejected = SimpleNamespace(confirmed=False, severity=None)
    sarif = build_sarif([confirmed, rejected])
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "PY_SQL_INTERPOLATION"
    assert run["results"][0]["properties"]["humanDecision"] == "approved"
