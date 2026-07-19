from __future__ import annotations

import contextlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from app.cli import main
from app.services.local_sarif import build_local_sarif
from app.services.local_scan import (
    EXIT_CONFIGURATION,
    EXIT_POLICY_BLOCK,
    LocalScanError,
    build_local_scan_report,
    verify_report_sha256,
)

SQL_VULN = '''def handler(request, cursor):
    user_id = request.args["id"]
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
'''


def git(root: Path, *args: str) -> None:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def init_repo(root: Path) -> None:
    git(root, "init", "-q")
    git(root, "config", "user.name", "Sentinel Test")
    git(root, "config", "user.email", "sentinel@example.invalid")


def commit_all(root: Path, message: str) -> None:
    git(root, "add", "-A")
    git(root, "commit", "-qm", message)


def test_full_local_scan_respects_gitignore_redacts_secrets_and_skips_unsafe_files(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(SQL_VULN, encoding="utf-8")
    secret = "sk-proj-abcdefghijklmnopqrstuvwx"
    (tmp_path / "secret.py").write_text(f'OPENAI_API_KEY = "{secret}"\n', encoding="utf-8")
    (tmp_path / "ignored.py").write_text('password = "ignored-secret-value"\n', encoding="utf-8")
    (tmp_path / "binary.py").write_bytes(b"value = 1\0binary")
    outside = tmp_path.parent / "outside.py"
    outside.write_text(SQL_VULN, encoding="utf-8")
    symlink_created = False
    with contextlib.suppress(OSError):
        os.symlink(outside, tmp_path / "linked.py")
        symlink_created = True

    report = build_local_scan_report(tmp_path)

    paths = {item["file_path"] for item in report["findings"]}
    assert "app.py" in paths
    assert "secret.py" in paths
    assert "ignored.py" not in paths
    assert "linked.py" not in paths
    assert report["inventory"]["skipped"]["binary_or_non_utf8"] == 1
    if symlink_created:
        assert report["inventory"]["skipped"]["symlink"] == 1
    assert report["safety"] == {
        "source_executed": False,
        "dependencies_installed": False,
        "patches_applied": False,
        "symlinks_followed": False,
        "snippets_secret_sanitized": True,
    }
    secret_finding = next(item for item in report["findings"] if item["file_path"] == "secret.py")
    assert secret not in secret_finding["snippet"]
    assert "<REDACTED_SECRET_" in secret_finding["snippet"]
    assert secret_finding["redaction_count"] >= 1
    assert verify_report_sha256(report)


def test_non_git_fallback_respects_root_gitignore_and_prunes_vendor_directories(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    (tmp_path / "kept.py").write_text(SQL_VULN, encoding="utf-8")
    (tmp_path / "ignored.py").write_text(SQL_VULN, encoding="utf-8")
    vendor = tmp_path / "node_modules" / "package"
    vendor.mkdir(parents=True)
    (vendor / "unsafe.js").write_text("eval(req.body.code);\n", encoding="utf-8")

    report = build_local_scan_report(tmp_path)

    selected = {item["path"] for item in report["inventory"]["files"]}
    assert selected == {"kept.py"}
    assert {item["file_path"] for item in report["findings"]} == {"kept.py"}
    assert report["mode"]["git_work_tree"] is False


def test_changed_only_scans_committed_delta_and_untracked_files_not_unchanged_debt(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "unchanged_vuln.py").write_text(SQL_VULN, encoding="utf-8")
    (tmp_path / "changed.py").write_text("value = 1\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")
    (tmp_path / "changed.py").write_text(SQL_VULN, encoding="utf-8")
    commit_all(tmp_path, "introduce changed vulnerability")
    (tmp_path / "untracked.js").write_text("fetch(req.query.url);\n", encoding="utf-8")

    report = build_local_scan_report(tmp_path, changed_only=True, base_ref="HEAD~1")

    selected = {item["path"] for item in report["inventory"]["files"]}
    assert selected == {"changed.py", "untracked.js"}
    finding_paths = {item["file_path"] for item in report["findings"]}
    assert finding_paths == {"changed.py", "untracked.js"}
    assert "unchanged_vuln.py" not in finding_paths
    assert report["baseline"]["comparison_scope"] == "partial"
    assert report["baseline"]["resolved_count"] is None


def test_baseline_fingerprint_survives_line_move_and_no_new_risk_blocks_only_introduced(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "app.py").write_text(SQL_VULN, encoding="utf-8")
    baseline = build_local_scan_report(tmp_path)
    baseline_path = tmp_path / "sentinel-baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")

    (tmp_path / "app.py").write_text("\n\n" + SQL_VULN, encoding="utf-8")
    (tmp_path / "new.js").write_text("eval(req.body.code);\n", encoding="utf-8")
    current = build_local_scan_report(
        tmp_path,
        baseline=baseline_path,
        fail_on="new",
        fail_confidence=0.8,
    )

    states = {(item["file_path"], item["baseline_state"]) for item in current["findings"]}
    assert ("app.py", "existing") in states
    assert ("new.js", "new") in states
    assert current["policy"]["blocked"] is True
    assert current["policy"]["blocker_count"] == 1
    assert current["policy"]["exit_code"] == EXIT_POLICY_BLOCK
    assert current["baseline"]["resolved_count"] == 0


def test_local_sarif_marks_candidates_as_unconfirmed_and_never_leaks_secret(tmp_path: Path) -> None:
    secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    (tmp_path / "token.js").write_text(f'const token = "{secret}";\n', encoding="utf-8")
    report = build_local_scan_report(tmp_path)

    sarif = build_local_sarif(report)
    serialized = json.dumps(sarif)
    result = sarif["runs"][0]["results"][0]

    assert secret not in serialized
    assert result["kind"] == "review"
    assert result["properties"]["confirmed"] is False
    assert result["properties"]["sourceExecuted"] is False
    assert result["partialFingerprints"]["sentinel/local/v1"]
    assert sarif["runs"][0]["tool"]["driver"]["semanticVersion"] == "2.2.0"


def test_cli_writes_json_and_sarif_and_uses_stable_policy_exit_code(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(SQL_VULN, encoding="utf-8")
    report_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"

    exit_code = main(
        [
            "scan",
            str(tmp_path),
            "--fail-on",
            "any",
            "--fail-confidence",
            "0.8",
            "--json-output",
            str(report_path),
            "--sarif-output",
            str(sarif_path),
            "--quiet",
        ]
    )

    assert exit_code == EXIT_POLICY_BLOCK
    assert json.loads(report_path.read_text())["schema_version"] == "sentinel-local-scan-v1"
    assert json.loads(sarif_path.read_text())["version"] == "2.1.0"


def test_changed_only_rejects_non_git_directory(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(SQL_VULN, encoding="utf-8")
    with pytest.raises(LocalScanError, match="requires a Git work tree"):
        build_local_scan_report(tmp_path, changed_only=True)


def test_invalid_baseline_returns_configuration_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "app.py").write_text(SQL_VULN, encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"schema_version":"other"}', encoding="utf-8")

    exit_code = main(["scan", str(tmp_path), "--baseline", str(baseline)])

    assert exit_code == EXIT_CONFIGURATION
    assert "Baseline is not a Sentinel local scan" in capsys.readouterr().err


def test_local_cli_import_does_not_load_server_frameworks() -> None:
    result = subprocess.run(
        [
            os.sys.executable,
            "-c",
            (
                "import sys; import app.cli; "
                "assert 'sqlalchemy' not in sys.modules; "
                "assert 'fastapi' not in sys.modules; "
                "assert 'uvicorn' not in sys.modules"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_omit_snippets_removes_snippet_field_but_preserves_redaction_metadata(tmp_path: Path) -> None:
    (tmp_path / "secret.py").write_text('password = "a-very-long-password"\n', encoding="utf-8")

    report = build_local_scan_report(tmp_path, include_snippets=False)

    finding = report["findings"][0]
    assert "snippet" not in finding
    assert finding["redaction_count"] == 1


@pytest.mark.skipif(os.name == "nt", reason="Executable hook fixture uses POSIX shell")
def test_changed_only_disables_repository_fsmonitor_and_external_diff(tmp_path: Path) -> None:
    init_repo(tmp_path)
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    commit_all(tmp_path, "baseline")

    marker = tmp_path / "executed.txt"
    helper = tmp_path / "malicious-helper.sh"
    helper.write_text(f'#!/bin/sh\necho executed >> "{marker}"\nexit 0\n', encoding="utf-8")
    helper.chmod(0o755)
    git(tmp_path, "config", "core.fsmonitor", str(helper))
    git(tmp_path, "config", "diff.external", str(helper))
    (tmp_path / "app.py").write_text(SQL_VULN, encoding="utf-8")

    report = build_local_scan_report(tmp_path, changed_only=True)

    assert report["inventory"]["selected_file_count"] == 1
    assert marker.exists() is False
