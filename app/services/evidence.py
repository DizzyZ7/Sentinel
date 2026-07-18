import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.version import (
    APP_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    PATCH_VALIDATOR_VERSION,
    POLICY_VERSION,
    STATIC_RULESET_VERSION,
)
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.decision import DecisionResponse
from app.schemas.evidence import (
    EvidenceFinding,
    EvidenceIntegrity,
    EvidenceScan,
    EvidenceVersions,
    FindingEvidenceBundle,
    LLMVerdictEvidence,
    PatchEvidence,
    StaticEvidence,
)
from app.schemas.llm_audit import LLMReviewRunResponse
from app.schemas.risk_intelligence import RiskIntelligenceResponse
from app.schemas.verification import RegressionVerificationResponse
from app.services.attack_paths import build_attack_path_response
from app.services.context_sanitizer import sanitize_context
from app.services.llm_review import PROMPT_VERSION, SCHEMA_VERSION
from app.services.policy import evaluate_gate
from app.services.risk_intelligence import RISK_ENGINE_VERSION, build_risk_intelligence


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


def _safe_patch_bytes(scan: Scan, finding: Finding) -> bytes:
    if finding.patch_path:
        workspace = Path(scan.workspace_path).resolve()
        patch = Path(finding.patch_path).resolve()
        if patch.is_relative_to(workspace) and patch.is_file():
            return patch.read_bytes()
    return (finding.unified_diff or "").encode("utf-8")


def _changed_lines(diff: str | None) -> int:
    if not diff:
        return 0
    return sum(
        1
        for line in diff.splitlines()
        if (line.startswith("+") and not line.startswith("+++"))
        or (line.startswith("-") and not line.startswith("---"))
    )


def build_finding_evidence_bundle(
    scan: Scan,
    finding: Finding,
    all_findings: list[Finding],
    *,
    generated_at: datetime | None = None,
) -> FindingEvidenceBundle:
    generated_at = generated_at or datetime.now(UTC)
    sanitized_snippet = sanitize_context(finding.snippet)
    sanitized_diff = sanitize_context(finding.unified_diff or "")
    patch_bytes = _safe_patch_bytes(scan, finding)
    attack_paths = build_attack_path_response(scan.id, [finding])
    attack_path = attack_paths.paths[0] if attack_paths.paths else None
    gate = evaluate_gate(scan.id, all_findings)

    verification = (
        RegressionVerificationResponse.model_validate(finding.verification)
        if finding.verification
        else None
    )
    sections: dict[str, Any] = {
        "versions": EvidenceVersions(
            app=APP_VERSION,
            evidence_schema=EVIDENCE_SCHEMA_VERSION,
            static_ruleset=STATIC_RULESET_VERSION,
            prompt=PROMPT_VERSION,
            llm_output_schema=SCHEMA_VERSION,
            patch_validator=PATCH_VALIDATOR_VERSION,
            regression_verifier=verification.verifier_version if verification else None,
            policy=POLICY_VERSION,
            risk_engine=RISK_ENGINE_VERSION,
        ).model_dump(mode="json"),
        "scan": EvidenceScan(
            id=scan.id,
            status=scan.status,
            source_type=scan.source_type,
            source_url=scan.source_url,
            original_filename=scan.original_filename,
            file_count=scan.file_count,
            candidate_count=scan.candidate_count,
            finding_count=scan.finding_count,
            risk_score=scan.risk_score,
            repository_structure_sha256=_sha256(scan.structure),
            created_at=scan.created_at,
            completed_at=scan.completed_at,
        ).model_dump(mode="json"),
        "finding": EvidenceFinding(
            id=finding.id,
            rule_id=finding.rule_id,
            title=finding.title,
            file_path=finding.file_path,
            line=finding.line,
            end_line=finding.end_line,
            language=finding.language,
            static_confidence=finding.static_confidence,
            llm_status=finding.llm_status,
            confirmed=finding.confirmed,
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            confidence=finding.confidence,
            cwe=finding.cwe,
        ).model_dump(mode="json"),
        "static_evidence": StaticEvidence(
            rationale=finding.static_rationale,
            sanitized_snippet=sanitized_snippet.text,
            redaction_summary=sanitized_snippet.summary,
        ).model_dump(mode="json"),
        "llm_verdict": LLMVerdictEvidence(
            confirmed=finding.confirmed,
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            confidence=finding.confidence,
            explanation=finding.explanation,
            attack_scenario=finding.attack_scenario,
            recommendation=finding.recommendation,
            cwe=finding.cwe,
        ).model_dump(mode="json"),
        "llm_review": (
            LLMReviewRunResponse.model_validate(finding.llm_review).model_dump(mode="json")
            if finding.llm_review
            else None
        ),
        "patch": PatchEvidence(
            available=bool(finding.unified_diff or finding.patch_path),
            valid=finding.patch_valid,
            error=finding.patch_error,
            sha256=hashlib.sha256(patch_bytes).hexdigest() if patch_bytes else None,
            size_bytes=len(patch_bytes),
            changed_lines=_changed_lines(finding.unified_diff),
            sanitized_unified_diff=sanitized_diff.text or None,
            redaction_summary=sanitized_diff.summary,
        ).model_dump(mode="json"),
        "regression_proof": verification.model_dump(mode="json") if verification else None,
        "human_decision": (
            DecisionResponse.model_validate(finding.decision).model_dump(mode="json")
            if finding.decision
            else None
        ),
        "release_gate": gate.model_dump(mode="json"),
        "attack_path": attack_path.model_dump(mode="json") if attack_path else None,
        "risk_intelligence": (
            RiskIntelligenceResponse.model_validate(
                getattr(finding, "risk_intelligence", None) or build_risk_intelligence(finding)
            ).model_dump(mode="json")
            if finding.confirmed and finding.severity
            else None
        ),
    }
    section_sha256 = {name: _sha256(value) for name, value in sections.items()}
    payload_sha256 = _sha256(sections)

    return FindingEvidenceBundle(
        generated_at=generated_at,
        **sections,
        integrity=EvidenceIntegrity(
            section_sha256=section_sha256,
            payload_sha256=payload_sha256,
        ),
    )
