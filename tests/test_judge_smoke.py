import hashlib
import json

import httpx

from scripts.verify_judge_demo import run_judge_smoke, verify_evidence_bundle


def canonical_sha256(value):
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def evidence_bundle(scan_id, finding, gate):
    proof = finding.get("verification")
    sections = {
        "versions": {"app": "2.0.1"},
        "scan": {"id": scan_id},
        "finding": {
            "id": finding["id"],
            "file_path": finding["file_path"],
        },
        "static_evidence": {},
        "llm_verdict": {"confirmed": finding["confirmed"]},
        "llm_review": {},
        "patch": {"valid": finding["patch_valid"]},
        "regression_proof": proof,
        "human_decision": None,
        "release_gate": gate,
        "attack_path": None,
        "security_policy_compliance": None,
        "exception_governance": None,
        "security_sla": None,
        "security_posture": None,
        "security_objective": None,
        "risk_intelligence": None,
    }
    return {
        "bundle_type": "sentinel-finding-evidence",
        "generated_at": "2026-07-19T00:00:00Z",
        **sections,
        "integrity": {
            "algorithm": "sha256",
            "canonicalization": "json-sort-keys-utf8-v1",
            "section_sha256": {key: canonical_sha256(value) for key, value in sections.items()},
            "payload_sha256": canonical_sha256(sections),
        },
    }


def test_judge_smoke_verifies_complete_three_outcome_contract() -> None:
    scan_id = "scan-1"
    findings = [
        {
            "id": "finding-1",
            "file_path": "confirmed_sql.py",
            "confirmed": True,
            "patch_valid": True,
            "verification": {"status": "passed", "source_executed": False},
        },
        {
            "id": "finding-2",
            "file_path": "safe_constant.py",
            "confirmed": False,
            "patch_valid": None,
            "verification": None,
        },
        {
            "id": "finding-3",
            "file_path": "weak_patch.py",
            "confirmed": True,
            "patch_valid": True,
            "verification": {"status": "failed", "source_executed": False},
        },
    ]
    gate = {
        "state": "blocked",
        "passed": False,
        "blockers": [
            {"file_path": "confirmed_sql.py"},
            {"file_path": "weak_patch.py"},
        ],
    }
    bundles = {item["id"]: evidence_bundle(scan_id, item, gate) for item in findings}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/health":
            return httpx.Response(200, json={"status": "ok", "service": "sentinel", "version": "2.0.1"})
        if path == "/scan/demo":
            return httpx.Response(202, json={"scan_id": scan_id, "status": "queued"})
        if path == f"/scan/{scan_id}/progress":
            return httpx.Response(200, json={"status": "completed", "error": None})
        if path == f"/scan/{scan_id}/report":
            return httpx.Response(
                200,
                json={
                    "candidate_count": 3,
                    "finding_count": 2,
                    "findings": findings,
                },
            )
        if path == f"/scan/{scan_id}/gate":
            return httpx.Response(200, json=gate)
        if path == f"/scan/{scan_id}/events":
            stages = ["queued", "ingesting", "indexing", "prefiltering", "reviewing", "finalizing", "completed"]
            return httpx.Response(
                200,
                json=[{"stage": stage, "percent": 100 if stage == "completed" else 50} for stage in stages],
            )
        if path == f"/scan/{scan_id}/llm-reviews":
            return httpx.Response(
                200,
                json={
                    "summary": {"total": 3, "completed": 3, "failed": 0},
                    "reviews": [
                        {"model": "sentinel-deterministic-demo-replay"},
                        {"model": "sentinel-deterministic-demo-replay"},
                        {"model": "sentinel-deterministic-demo-replay"},
                    ],
                },
            )
        marker = "/evidence-bundle"
        if marker in path:
            finding_id = path.split("/")[-2]
            bundle = bundles[finding_id]
            return httpx.Response(
                200,
                json=bundle,
                headers={"X-Sentinel-Evidence-SHA256": bundle["integrity"]["payload_sha256"]},
            )
        return httpx.Response(404, json={"detail": path})

    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test") as client:
        result = run_judge_smoke(
            "http://test",
            timeout_seconds=1,
            poll_interval_seconds=0.01,
            client=client,
        )

    assert result["status"] == "passed"
    assert result["summary"]["failed"] == 0
    assert result["observed"]["gate_state"] == "blocked"
    assert set(result["observed"]["evidence_payload_sha256"]) == {
        "confirmed_sql.py",
        "safe_constant.py",
        "weak_patch.py",
    }
    assert {item["key"] for item in result["checks"]} >= {
        "three_outcome_contract",
        "fail_closed_gate",
        "deterministic_replay_audit",
        "evidence:confirmed_sql.py",
        "evidence:safe_constant.py",
        "evidence:weak_patch.py",
    }


def test_evidence_integrity_detects_tampered_section_and_header() -> None:
    finding = {
        "id": "finding-1",
        "file_path": "confirmed_sql.py",
        "confirmed": True,
        "patch_valid": True,
        "verification": {"status": "passed", "source_executed": False},
    }
    gate = {"state": "blocked", "passed": False, "blockers": []}
    bundle = evidence_bundle("scan-1", finding, gate)
    bundle["finding"]["file_path"] = "tampered.py"

    errors = verify_evidence_bundle(bundle, header_digest="0" * 64)

    assert any("Section finding hash mismatch" in item for item in errors)
    assert any("Canonical payload hash mismatch" in item for item in errors)
    assert any("X-Sentinel-Evidence-SHA256" in item for item in errors)


def test_judge_smoke_returns_failure_with_actionable_outcome_detail() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok", "service": "sentinel", "version": "2.0.1"})
        if request.url.path == "/scan/demo":
            return httpx.Response(202, json={"scan_id": "broken", "status": "queued"})
        if request.url.path == "/scan/broken/progress":
            return httpx.Response(200, json={"status": "completed", "error": None})
        if request.url.path == "/scan/broken/report":
            return httpx.Response(200, json={"candidate_count": 2, "finding_count": 1, "findings": []})
        if request.url.path == "/scan/broken/gate":
            return httpx.Response(500, json={"detail": "gate unavailable"})
        return httpx.Response(404, json={"detail": request.url.path})

    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test") as client:
        result = run_judge_smoke("http://test", timeout_seconds=1, client=client)

    assert result["status"] == "failed"
    assert any(item["key"] == "three_outcome_contract" and item["status"] == "failed" for item in result["checks"])
    assert any(item["key"] == "execution" and "gate unavailable" in item["detail"] for item in result["checks"])
