import urllib.error

from app.services import ci_gate_client as check_delta


def test_build_url_and_exit_code_contract() -> None:
    url = check_delta.build_url("http://localhost:8000/", "current id", "baseline", "high", True)
    assert "/scan/current%20id/ci-gate?" in url
    assert "baseline_scan_id=baseline" in url
    assert check_delta.evaluate_exit_code(200, {"schema_version": "sentinel-ci-gate-v1", "exit_code": 0}) == 0
    assert check_delta.evaluate_exit_code(409, {"schema_version": "sentinel-ci-gate-v1", "exit_code": 1}) == 1
    assert check_delta.evaluate_exit_code(500, {"detail": "error"}) == 2


def test_cli_returns_security_regression_exit_code(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        check_delta,
        "request_gate",
        lambda url: (409, {"schema_version": "sentinel-ci-gate-v1", "exit_code": 1, "state": "blocked"}),
    )
    result = check_delta.main(["--current-scan-id", "current"])
    assert result == 1
    assert '"state": "blocked"' in capsys.readouterr().out


def test_cli_returns_operational_exit_code(monkeypatch, capsys) -> None:
    def fail(url: str):
        raise urllib.error.URLError("DNS unavailable")

    monkeypatch.setattr(check_delta, "request_gate", fail)
    result = check_delta.main(["--current-scan-id", "current"])
    assert result == 2
    assert '"exit_code": 2' in capsys.readouterr().out
