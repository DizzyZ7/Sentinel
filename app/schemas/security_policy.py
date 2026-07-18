from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.policy import GateResponse

Severity = Literal["low", "medium", "high", "critical"]
RequirementThreshold = Literal["low", "medium", "high", "critical", "never"]
PolicySource = Literal["inferred", "declared", "built_in", "preview"]
Exposure = Literal["unknown", "internal", "partner", "public"]
DataClassification = Literal["public", "internal", "confidential", "restricted"]
Criticality = Literal["low", "medium", "high", "critical"]
Environment = Literal["unknown", "development", "staging", "production"]


class SecurityPolicyOverride(BaseModel):
    override_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    name: str = Field(min_length=1, max_length=180)
    enabled: bool = True
    asset_ids: list[str] = Field(default_factory=list, max_length=50)
    path_patterns: list[str] = Field(default_factory=list, max_length=30)
    exposures: list[Exposure] = Field(default_factory=list)
    data_classifications: list[DataClassification] = Field(default_factory=list)
    criticalities: list[Criticality] = Field(default_factory=list)
    environments: list[Environment] = Field(default_factory=list)
    attack_surfaces: list[str] = Field(default_factory=list, max_length=30)
    severities: list[Severity] = Field(default_factory=list)
    block_on: Severity | None = None
    require_valid_patch: bool = False
    require_passed_proof: bool = False
    require_human_approval: bool = False

    @field_validator("path_patterns")
    @classmethod
    def validate_patterns(cls, patterns: list[str]) -> list[str]:
        normalized: list[str] = []
        for pattern in patterns:
            value = pattern.strip().replace("\\", "/")
            if not value or len(value) > 240 or "\x00" in value:
                raise ValueError("Path patterns must be non-empty and at most 240 characters")
            if value.startswith("/") or ".." in value.split("/"):
                raise ValueError("Path patterns must be repository-relative and cannot contain '..'")
            normalized.append(value)
        return normalized

    @field_validator("asset_ids", "attack_surfaces")
    @classmethod
    def normalize_strings(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip()[:120] for value in values if value.strip()))


class SecurityPolicyDocument(BaseModel):
    policy_name: str = Field(min_length=1, max_length=180)
    base_block_on: Severity = "high"
    fail_closed_on_unreviewed: bool = True
    unreviewed_confidence_threshold: float = Field(default=0.9, ge=0.0, le=1.0)
    require_valid_patch_from: RequirementThreshold = "high"
    require_passed_proof_from: RequirementThreshold = "high"
    require_human_approval_from: RequirementThreshold = "high"
    production_block_on: Severity | None = "high"
    public_asset_block_on: Severity | None = "medium"
    restricted_data_block_on: Severity | None = "medium"
    critical_asset_block_on: Severity | None = "medium"
    frameworks: list[str] = Field(default_factory=list, max_length=20)
    overrides: list[SecurityPolicyOverride] = Field(default_factory=list, max_length=100)

    @field_validator("frameworks")
    @classmethod
    def normalize_frameworks(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip()[:80] for value in values if value.strip()))

    @model_validator(mode="after")
    def unique_override_ids(self):
        ids = [item.override_id for item in self.overrides]
        if len(ids) != len(set(ids)):
            raise ValueError("Security policy override IDs must be unique")
        return self


class SecurityPolicyProfileResponse(BaseModel):
    profile_id: str
    root_scan_id: str
    version: int
    source: PolicySource
    policy_sha256: str
    document: SecurityPolicyDocument
    created_at: datetime | None = None
    assigned_to_current_scan: bool = False


class SecurityPolicyStatus(BaseModel):
    scan_id: str
    root_scan_id: str
    assigned_profile: SecurityPolicyProfileResponse
    latest_profile: SecurityPolicyProfileResponse
    versions: list[SecurityPolicyProfileResponse]
    next_rescan_uses_version: int


class PolicyFindingResult(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    file_path: str
    line: int
    severity: str | None
    effective_block_on: Severity
    in_scope: bool
    context_asset_id: str | None
    context_exposure: str
    context_data_classification: str
    context_criticality: str
    context_environment: str
    matched_override_ids: list[str]
    required_controls: list[str]
    satisfied_controls: list[str]
    blocker_reasons: list[str]


class PolicyComplianceSummary(BaseModel):
    evaluated_findings: int
    compliant_findings: int
    blocking_findings: int
    unreviewed_blockers: int
    matched_overrides: int


class SecurityPolicyCompliance(BaseModel):
    schema_version: str = "sentinel-policy-compliance-v1"
    scan_id: str
    state: Literal["passed", "blocked"]
    passed: bool
    policy_profile_id: str
    policy_version: int
    policy_sha256: str
    policy_name: str
    base_release_gate: GateResponse
    summary: PolicyComplianceSummary
    results: list[PolicyFindingResult]


class SecurityPolicyPreview(BaseModel):
    scan_id: str
    source: Literal["preview"] = "preview"
    policy_sha256: str
    compliance: SecurityPolicyCompliance


class PolicyComplianceComparisonSummary(BaseModel):
    baseline_blockers: int
    current_blockers: int
    introduced: int
    resolved: int
    persistent: int
    state_changed: bool


class PolicyComplianceComparison(BaseModel):
    schema_version: str = "sentinel-policy-comparison-v1"
    baseline_scan_id: str
    current_scan_id: str
    baseline: SecurityPolicyCompliance
    current: SecurityPolicyCompliance
    summary: PolicyComplianceComparisonSummary
