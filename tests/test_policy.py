from types import SimpleNamespace

from app.services.policy import evaluate_gate


def finding(**overrides):
    values = {
        "id": "f1",
        "rule_id": "PY_SQL_INTERPOLATION",
        "title": "SQL injection",
        "file_path": "app.py",
        "line": 10,
        "confirmed": True,
        "severity": "high",
        "patch_valid": True,
        "decision": None,
        "llm_status": "completed",
        "static_confidence": 0.96,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_gate_blocks_unapproved_high_finding() -> None:
    gate = evaluate_gate("scan-1", [finding()])
    assert gate.passed is False
    assert "awaiting explicit human approval" in gate.blockers[0].reason


def test_gate_passes_approved_valid_patch() -> None:
    gate = evaluate_gate(
        "scan-1",
        [finding(decision=SimpleNamespace(decision="approved"))],
    )
    assert gate.passed is True
    assert gate.remediated_findings == 1


def test_gate_fails_closed_when_deep_review_is_missing() -> None:
    gate = evaluate_gate(
        "scan-1",
        [
            finding(
                confirmed=None,
                severity=None,
                patch_valid=None,
                llm_status="skipped",
                static_confidence=0.97,
            )
        ],
    )
    assert gate.passed is False
    assert "fails closed" in gate.blockers[0].reason
