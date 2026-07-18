from datetime import datetime

from pydantic import BaseModel

from app.schemas.attack_path import AttackPath
from app.schemas.decision import DecisionResponse
from app.schemas.llm_audit import LLMReviewRunResponse
from app.schemas.policy import GateResponse
from app.schemas.risk_intelligence import RiskIntelligenceResponse
from app.schemas.security_policy import SecurityPolicyCompliance
from app.schemas.verification import RegressionVerificationResponse


class EvidenceVersions(BaseModel):
    app: str
    evidence_schema: str
    static_ruleset: str
    prompt: str
    llm_output_schema: str
    patch_validator: str
    regression_verifier: str | None
    policy: str
    risk_engine: str
    security_policy_engine: str


class EvidenceScan(BaseModel):
    id: str
    status: str
    source_type: str
    source_url: str | None
    original_filename: str | None
    file_count: int
    candidate_count: int
    finding_count: int
    risk_score: float
    repository_structure_sha256: str
    created_at: datetime
    completed_at: datetime | None


class EvidenceFinding(BaseModel):
    id: str
    rule_id: str
    title: str
    file_path: str
    line: int
    end_line: int
    language: str
    static_confidence: float
    llm_status: str
    confirmed: bool | None
    severity: str | None
    cvss_score: float | None
    confidence: float | None
    cwe: str | None


class StaticEvidence(BaseModel):
    rationale: str
    sanitized_snippet: str
    redaction_summary: dict


class LLMVerdictEvidence(BaseModel):
    confirmed: bool | None
    severity: str | None
    cvss_score: float | None
    confidence: float | None
    explanation: str | None
    attack_scenario: str | None
    recommendation: str | None
    cwe: str | None


class PatchEvidence(BaseModel):
    available: bool
    valid: bool | None
    error: str | None
    sha256: str | None
    size_bytes: int
    changed_lines: int
    sanitized_unified_diff: str | None
    redaction_summary: dict


class EvidenceIntegrity(BaseModel):
    algorithm: str = "sha256"
    canonicalization: str = "json-sort-keys-utf8-v1"
    section_sha256: dict[str, str]
    payload_sha256: str


class FindingEvidenceBundle(BaseModel):
    bundle_type: str = "sentinel-finding-evidence"
    generated_at: datetime
    versions: EvidenceVersions
    scan: EvidenceScan
    finding: EvidenceFinding
    static_evidence: StaticEvidence
    llm_verdict: LLMVerdictEvidence
    llm_review: LLMReviewRunResponse | None
    patch: PatchEvidence
    regression_proof: RegressionVerificationResponse | None
    human_decision: DecisionResponse | None
    release_gate: GateResponse
    attack_path: AttackPath | None
    risk_intelligence: RiskIntelligenceResponse | None
    security_policy_compliance: SecurityPolicyCompliance | None
    integrity: EvidenceIntegrity
