from datetime import UTC, datetime
from types import SimpleNamespace

from app.services.comparison import build_scan_comparison, compare_findings, finding_fingerprint


def finding(
    id: str,
    *,
    rule_id: str = "PY-SQL-INTERPOLATION",
    file_path: str = "app.py",
    line: int = 10,
    snippet: str = 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
    confirmed: bool | None = True,
    severity: str | None = "high",
    llm_status: str = "completed",
    static_confidence: float = 0.95,
):
    return SimpleNamespace(
        id=id,
        rule_id=rule_id,
        title=rule_id.replace("-", " ").title(),
        file_path=file_path,
        line=line,
        end_line=line,
        language="python",
        snippet=snippet,
        confirmed=confirmed,
        severity=severity,
        static_confidence=static_confidence,
        llm_status=llm_status,
        patch_valid=False,
        verification=None,
        decision=None,
    )


def scan(id: str, findings: list, risk_score: float):
    return SimpleNamespace(id=id, findings=findings, risk_score=risk_score)


def test_fingerprint_ignores_line_movement_and_whitespace() -> None:
    before = finding("before", line=10, snippet='cursor.execute( f"SELECT {user_id}" )')
    after = finding("after", line=90, snippet='  cursor.execute(  f"SELECT {user_id}"  )  ')
    assert finding_fingerprint(before) == finding_fingerprint(after)


def test_comparison_classifies_persistent_changed_introduced_and_resolved() -> None:
    baseline = [
        finding("persistent-before", line=10),
        finding("changed-before", file_path="changed.py", snippet="eval(request.args['x'])"),
        finding("resolved-before", rule_id="PY-UNSAFE-YAML", file_path="old.py", snippet="yaml.load(body)"),
    ]
    current = [
        finding("persistent-after", line=44),
        finding("changed-after", file_path="changed.py", snippet="eval(request.form['code'])"),
        finding("introduced-after", rule_id="PY-SSRF", file_path="new.py", snippet="requests.get(request.args['url'])"),
    ]
    items = compare_findings(baseline, current)
    assert [item.state for item in items] == ["introduced", "changed", "persistent", "resolved"]
    changed = next(item for item in items if item.state == "changed")
    assert changed.baseline and changed.baseline.id == "changed-before"
    assert changed.current and changed.current.id == "changed-after"


def test_delta_gate_ignores_persistent_legacy_debt_but_blocks_new_high_risk() -> None:
    persistent_before = finding("legacy-before")
    persistent_after = finding("legacy-after", line=55)
    introduced = finding(
        "new-high",
        rule_id="PY-COMMAND-INJECTION",
        file_path="shell.py",
        snippet="os.system(user_input)",
    )
    comparison = build_scan_comparison(
        scan("baseline", [persistent_before], 35.0),
        scan("current", [persistent_after, introduced], 65.0),
        generated_at=datetime(2026, 7, 18, tzinfo=UTC),
    )
    assert comparison.baseline_gate.passed is False
    assert comparison.current_gate.passed is False
    assert comparison.delta_gate.passed is False
    assert comparison.summary.blocking_regressions == 1
    assert comparison.delta_gate.blockers[0].current_finding_id == "new-high"
    assert comparison.summary.persistent == 1
    assert comparison.summary.introduced == 1
    assert comparison.summary.risk_delta == 30.0


def test_delta_gate_passes_when_only_legacy_debt_persists() -> None:
    comparison = build_scan_comparison(
        scan("baseline", [finding("before")], 40.0),
        scan("current", [finding("after", line=100)], 40.0),
    )
    assert comparison.current_gate.passed is False
    assert comparison.delta_gate.passed is True
    assert comparison.delta_gate.blockers == []


def test_delta_gate_allows_a_new_finding_after_verified_human_approved_remediation() -> None:
    remediated = finding(
        "new-remediated",
        rule_id="PY-SSRF",
        file_path="client.py",
        snippet="requests.get(request.args['url'])",
    )
    remediated.patch_valid = True
    remediated.verification = SimpleNamespace(status="passed")
    remediated.decision = SimpleNamespace(decision="approved")
    comparison = build_scan_comparison(
        scan("baseline", [], 0.0),
        scan("current", [remediated], 20.0),
    )
    assert comparison.delta_gate.evaluated_regressions == 1
    assert comparison.delta_gate.passed is True
    assert comparison.delta_gate.blockers == []
