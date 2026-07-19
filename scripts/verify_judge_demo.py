from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

SCHEMA_VERSION = "sentinel-judge-smoke-v1"
EXPECTED_OUTCOMES = {
    "confirmed_sql.py": {
        "confirmed": True,
        "patch_valid": True,
        "verification_status": "passed",
    },
    "safe_constant.py": {
        "confirmed": False,
        "patch_valid": None,
        "verification_status": None,
    },
    "weak_patch.py": {
        "confirmed": True,
        "patch_valid": True,
        "verification_status": "failed",
    },
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def verify_evidence_bundle(payload: dict[str, Any], header_digest: str | None = None) -> list[str]:
    errors: list[str] = []
    integrity = payload.get("integrity")
    if not isinstance(integrity, dict):
        return ["Evidence Bundle has no integrity object."]

    section_hashes = integrity.get("section_sha256")
    payload_digest = integrity.get("payload_sha256")
    if not isinstance(section_hashes, dict) or not isinstance(payload_digest, str):
        return ["Evidence Bundle integrity fields are incomplete."]

    sections = {
        key: value
        for key, value in payload.items()
        if key not in {"bundle_type", "generated_at", "integrity"}
    }
    if set(section_hashes) != set(sections):
        missing = sorted(set(sections) - set(section_hashes))
        unexpected = sorted(set(section_hashes) - set(sections))
        errors.append(f"Section hash keys differ: missing={missing}, unexpected={unexpected}.")

    for name, value in sections.items():
        expected = section_hashes.get(name)
        actual = _sha256(value)
        if expected != actual:
            errors.append(f"Section {name} hash mismatch: expected={expected}, actual={actual}.")

    actual_payload_digest = _sha256(sections)
    if payload_digest != actual_payload_digest:
        errors.append(
            "Canonical payload hash mismatch: "
            f"expected={payload_digest}, actual={actual_payload_digest}."
        )
    if header_digest is not None and header_digest != payload_digest:
        errors.append(
            "X-Sentinel-Evidence-SHA256 does not match the payload: "
            f"header={header_digest}, payload={payload_digest}."
        )
    return errors


def _json(response: httpx.Response, label: str) -> Any:
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        body = response.text[:600]
        raise RuntimeError(f"{label} returned HTTP {response.status_code}: {body}") from exc
    try:
        return response.json()
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} returned invalid JSON: {response.text[:600]}") from exc


def _add_check(checks: list[dict[str, str]], key: str, passed: bool, detail: str) -> None:
    checks.append(
        {
            "key": key,
            "status": "passed" if passed else "failed",
            "detail": detail,
        }
    )


def run_judge_smoke(
    base_url: str,
    *,
    timeout_seconds: float = 120.0,
    poll_interval_seconds: float = 0.5,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    checks: list[dict[str, str]] = []
    scan_id: str | None = None
    app_version: str | None = None
    candidate_count: int | None = None
    confirmed_findings: int | None = None
    gate_state: str | None = None
    blocker_paths_observed: list[str] = []
    review_models: list[str] = []
    evidence_digests: dict[str, str] = {}
    owns_client = client is None
    active_client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=15.0)

    try:
        health = _json(active_client.get("/health"), "health check")
        app_version = health.get("version")
        health_ok = health.get("status") == "ok" and health.get("service") == "sentinel"
        _add_check(
            checks,
            "health",
            health_ok,
            f"service={health.get('service')}, status={health.get('status')}, version={health.get('version')}",
        )

        created = _json(active_client.post("/scan/demo", params={"mode": "replay"}), "demo creation")
        scan_id = created.get("scan_id")
        _add_check(
            checks,
            "demo_created",
            isinstance(scan_id, str) and bool(scan_id),
            f"scan_id={scan_id}, initial_status={created.get('status')}",
        )
        if not scan_id:
            raise RuntimeError("Demo creation did not return scan_id.")

        deadline = time.monotonic() + timeout_seconds
        progress: dict[str, Any] = {}
        while time.monotonic() < deadline:
            progress = _json(active_client.get(f"/scan/{scan_id}/progress"), "scan progress")
            if progress.get("status") in {"completed", "failed"}:
                break
            time.sleep(max(poll_interval_seconds, 0.01))
        else:
            raise RuntimeError(f"Demo scan did not complete within {timeout_seconds:.1f} seconds.")

        completed = progress.get("status") == "completed"
        _add_check(
            checks,
            "scan_completed",
            completed,
            f"status={progress.get('status')}, error={progress.get('error')}",
        )
        if not completed:
            raise RuntimeError(f"Demo scan finished with status={progress.get('status')}.")

        report = _json(active_client.get(f"/scan/{scan_id}/report", params={"format": "json"}), "report")
        findings = report.get("findings") if isinstance(report, dict) else None
        findings = findings if isinstance(findings, list) else []
        findings_by_path = {item.get("file_path"): item for item in findings if isinstance(item, dict)}

        candidate_count = report.get("candidate_count")
        confirmed_findings = report.get("finding_count")
        counts_ok = (
            candidate_count == 3
            and confirmed_findings == 2
            and set(findings_by_path) == set(EXPECTED_OUTCOMES)
        )
        _add_check(
            checks,
            "three_outcome_contract",
            counts_ok,
            (
                f"candidate_count={report.get('candidate_count')}, finding_count={report.get('finding_count')}, "
                f"files={sorted(findings_by_path)}"
            ),
        )

        for file_path, expected in EXPECTED_OUTCOMES.items():
            finding = findings_by_path.get(file_path)
            if finding is None:
                _add_check(checks, f"outcome:{file_path}", False, "Expected finding is missing.")
                continue
            verification = finding.get("verification")
            proof_status = verification.get("status") if isinstance(verification, dict) else None
            outcome_ok = (
                finding.get("confirmed") is expected["confirmed"]
                and finding.get("patch_valid") is expected["patch_valid"]
                and proof_status == expected["verification_status"]
            )
            _add_check(
                checks,
                f"outcome:{file_path}",
                outcome_ok,
                (
                    f"confirmed={finding.get('confirmed')}, patch_valid={finding.get('patch_valid')}, "
                    f"verification_status={proof_status}"
                ),
            )
            if isinstance(verification, dict):
                _add_check(
                    checks,
                    f"source_not_executed:{file_path}",
                    verification.get("source_executed") is False,
                    f"source_executed={verification.get('source_executed')}",
                )

        gate = _json(active_client.get(f"/scan/{scan_id}/gate"), "release gate")
        blocker_paths = {
            item.get("file_path")
            for item in gate.get("blockers", [])
            if isinstance(item, dict)
        }
        expected_blockers = {"confirmed_sql.py", "weak_patch.py"}
        gate_state = gate.get("state")
        blocker_paths_observed = sorted(path for path in blocker_paths if path)
        gate_ok = gate_state == "blocked" and gate.get("passed") is False
        blockers_ok = blocker_paths == expected_blockers
        _add_check(
            checks,
            "fail_closed_gate",
            gate_ok and blockers_ok,
            f"state={gate_state}, blocker_paths={blocker_paths_observed}",
        )

        events = _json(active_client.get(f"/scan/{scan_id}/events"), "scan events")
        stages = [item.get("stage") for item in events if isinstance(item, dict)]
        required_stages = {"queued", "ingesting", "indexing", "prefiltering", "reviewing", "finalizing", "completed"}
        event_ok = required_stages.issubset(set(stages)) and bool(events) and events[-1].get("percent") == 100
        _add_check(
            checks,
            "progress_contract",
            event_ok,
            f"stages={stages}, final_percent={events[-1].get('percent') if events else None}",
        )

        audit = _json(active_client.get(f"/scan/{scan_id}/llm-reviews"), "LLM audit")
        reviews = audit.get("reviews") if isinstance(audit, dict) else None
        reviews = reviews if isinstance(reviews, list) else []
        models = {item.get("model") for item in reviews if isinstance(item, dict)}
        review_models = sorted(model for model in models if model)
        audit_summary = audit.get("summary", {}) if isinstance(audit, dict) else {}
        audit_ok = (
            audit_summary.get("total") == 3
            and audit_summary.get("completed") == 3
            and audit_summary.get("failed") == 0
            and models == {"sentinel-deterministic-demo-replay"}
        )
        _add_check(
            checks,
            "deterministic_replay_audit",
            audit_ok,
            f"summary={audit_summary}, models={review_models}",
        )

        for file_path, finding in findings_by_path.items():
            finding_id = finding.get("id")
            if not finding_id:
                _add_check(checks, f"evidence:{file_path}", False, "Finding has no ID.")
                continue
            response = active_client.get(f"/scan/{scan_id}/findings/{finding_id}/evidence-bundle")
            bundle = _json(response, f"Evidence Bundle for {file_path}")
            header_digest = response.headers.get("X-Sentinel-Evidence-SHA256")
            errors = verify_evidence_bundle(bundle, header_digest)
            identity_ok = (
                bundle.get("scan", {}).get("id") == scan_id
                and bundle.get("finding", {}).get("id") == finding_id
                and bundle.get("finding", {}).get("file_path") == file_path
                and bundle.get("release_gate", {}).get("state") == "blocked"
            )
            evidence_ok = not errors and identity_ok
            digest = bundle.get("integrity", {}).get("payload_sha256")
            if isinstance(digest, str):
                evidence_digests[file_path] = digest
            _add_check(
                checks,
                f"evidence:{file_path}",
                evidence_ok,
                "integrity and identity verified" if evidence_ok else f"errors={errors}, identity_ok={identity_ok}",
            )

    except (httpx.HTTPError, RuntimeError, TypeError, ValueError) as exc:
        _add_check(checks, "execution", False, f"{type(exc).__name__}: {exc}")
    finally:
        if owns_client:
            active_client.close()

    completed_at = datetime.now(UTC)
    failed_checks = [item for item in checks if item["status"] == "failed"]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "passed" if not failed_checks else "failed",
        "base_url": base_url.rstrip("/"),
        "scan_id": scan_id,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_ms": max(0, round((completed_at - started_at).total_seconds() * 1000)),
        "summary": {
            "total": len(checks),
            "passed": len(checks) - len(failed_checks),
            "failed": len(failed_checks),
        },
        "observed": {
            "app_version": app_version,
            "candidate_count": candidate_count,
            "confirmed_findings": confirmed_findings,
            "gate_state": gate_state,
            "blocker_paths": blocker_paths_observed,
            "review_models": review_models,
            "evidence_payload_sha256": dict(sorted(evidence_digests.items())),
        },
        "checks": checks,
    }


def cli() -> int:
    parser = argparse.ArgumentParser(description="Verify Sentinel's complete deterministic judge path.")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--poll-interval", type=float, default=0.5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = run_judge_smoke(
        args.base_url,
        timeout_seconds=args.timeout,
        poll_interval_seconds=args.poll_interval,
    )
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    sys.stdout.write(serialized)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(cli())
