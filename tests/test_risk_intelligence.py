from types import SimpleNamespace

from app.services.risk_intelligence import build_executive_report, build_risk_intelligence


def finding(**changes):
    values = {
        "id": "f1",
        "rule_id": "PY_SQL_INTERPOLATION",
        "title": "SQL injection",
        "file_path": "app/api/users.py",
        "line": 12,
        "severity": "high",
        "confirmed": True,
        "confidence": 0.97,
        "static_confidence": 0.95,
        "llm_status": "completed",
        "patch_valid": False,
        "decision": None,
        "verification": None,
        "risk_intelligence": None,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_risk_engine_is_deterministic_and_asset_aware() -> None:
    first = build_risk_intelligence(finding())
    second = build_risk_intelligence(finding())
    assert first is not None and second is not None
    assert first.inherent_risk_score == second.inherent_risk_score
    assert first.asset_type == "data_service"
    assert first.attack_surface == "data"
    assert first.exposure == "public"
    assert first.priority in {"immediate", "before_release"}
    assert first.scoring_factors["formula"].startswith("40% technical")


def test_verified_and_approved_remediation_reduces_residual_risk() -> None:
    exposed = build_risk_intelligence(finding())
    remediated = build_risk_intelligence(
        finding(
            patch_valid=True,
            verification=SimpleNamespace(status="passed"),
            decision=SimpleNamespace(decision="approved"),
        )
    )
    assert exposed is not None and remediated is not None
    assert remediated.inherent_risk_score == exposed.inherent_risk_score
    assert remediated.residual_risk_score < exposed.residual_risk_score
    assert remediated.scoring_factors["remediation_multiplier"] == 0.15


def test_unconfirmed_candidate_has_no_business_risk_record() -> None:
    assert build_risk_intelligence(finding(confirmed=False, severity=None)) is None


def test_executive_report_prioritizes_highest_residual_risk() -> None:
    sql = finding(id="sql")
    command = finding(
        id="cmd",
        rule_id="PY_COMMAND_INJECTION",
        title="Command injection",
        file_path="app/admin/runner.py",
        severity="critical",
        confidence=0.99,
    )
    dismissed = finding(id="safe", confirmed=False, severity=None)
    report = build_executive_report("scan-1", [sql, command, dismissed])
    assert report.summary.confirmed_findings == 2
    assert report.summary.immediate_actions >= 1
    assert report.top_risks[0].finding_id == "cmd"
    assert report.summary.top_attack_surface == "code_execution"
    assert report.gate.passed is False
