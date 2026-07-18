import hashlib
import json
from datetime import UTC, datetime

from app.models.finding import Finding
from app.models.scan import Scan
from app.models.verification import RegressionVerification
from app.services.evidence import build_finding_evidence_bundle


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def test_evidence_bundle_is_secret_safe_and_self_verifying(tmp_path):
    now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
    workspace = tmp_path / "scan"
    workspace.mkdir()
    patch = workspace / "fix.patch"
    patch.write_text(
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-API_KEY = 'sk-proj-supersecretvalue123456'\n"
        "+API_KEY = '<read-from-env>'\n",
        encoding="utf-8",
    )
    scan = Scan(
        id="scan-1",
        status="completed",
        source_type="zip",
        original_filename="demo.zip",
        workspace_path=str(workspace),
        structure=[{"path": "app.py", "language": "python"}],
        file_count=1,
        candidate_count=1,
        finding_count=1,
        risk_score=15.0,
        created_at=now,
        completed_at=now,
    )
    finding = Finding(
        id="finding-1",
        scan_id=scan.id,
        rule_id="hardcoded-secret",
        title="Hardcoded API key",
        file_path="app.py",
        line=1,
        end_line=1,
        language="python",
        snippet="API_KEY = 'sk-proj-supersecretvalue123456'",
        static_rationale="A credential-like value is committed to source.",
        static_confidence=0.99,
        llm_status="completed",
        confirmed=True,
        severity="high",
        cvss_score=8.0,
        confidence=0.98,
        explanation="The credential is exposed in source control.",
        attack_scenario="A repository reader can reuse the credential.",
        recommendation="Load the value from a secret manager.",
        cwe="CWE-798",
        unified_diff=patch.read_text(encoding="utf-8"),
        patch_path=str(patch),
        patch_valid=True,
        created_at=now,
    )
    finding.verification = RegressionVerification(
        finding_id=finding.id,
        status="passed",
        mode="non_executing_static_regression",
        verifier_version="0.4.0",
        before_detected=True,
        after_detected=False,
        patch_applied=True,
        source_executed=False,
        before_digest="a" * 64,
        after_digest="b" * 64,
        checks=[{"name": "rule_removed", "status": "passed", "detail": "Signal removed"}],
        verified_at=now,
    )
    scan.findings = [finding]

    bundle = build_finding_evidence_bundle(scan, finding, [finding], generated_at=now)
    payload = bundle.model_dump(mode="json")
    rendered = json.dumps(payload, ensure_ascii=False)

    assert "sk-proj-supersecretvalue123456" not in rendered
    assert "<REDACTED_SECRET_" in bundle.static_evidence.sanitized_snippet
    assert "<REDACTED_SECRET_" in (bundle.patch.sanitized_unified_diff or "")
    assert bundle.patch.sha256 == hashlib.sha256(patch.read_bytes()).hexdigest()
    assert bundle.release_gate.passed is False
    assert bundle.release_gate.blockers[0].finding_id == finding.id
    assert bundle.attack_path is not None

    section_names = [
        "versions",
        "scan",
        "finding",
        "static_evidence",
        "llm_verdict",
        "llm_review",
        "patch",
        "regression_proof",
        "human_decision",
        "release_gate",
        "attack_path",
    ]
    sections = {name: payload[name] for name in section_names}
    assert bundle.integrity.payload_sha256 == canonical_sha256(sections)
    for name in section_names:
        assert bundle.integrity.section_sha256[name] == canonical_sha256(sections[name])
