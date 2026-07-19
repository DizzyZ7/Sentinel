from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Criticality = Literal["low", "medium", "high", "critical"]
PortfolioState = Literal["passed", "at_risk", "blocked", "insufficient_evidence"]
MemberReadiness = Literal["passed", "at_risk", "blocked"]
EvidenceState = Literal["current", "stale", "missing", "failed", "in_progress", "ambiguous_head"]
CheckStatus = Literal["met", "missed"]


class PortfolioGovernanceDocument(BaseModel):
    profile_name: str = Field(default="Sentinel portfolio governance", min_length=1, max_length=180)
    max_scan_age_days: int = Field(default=30, ge=1, le=3650)
    max_missing_members: int = Field(default=0, ge=0, le=100000)
    max_stale_members: int = Field(default=0, ge=0, le=100000)
    max_unavailable_members: int = Field(default=0, ge=0, le=100000)
    max_ambiguous_heads: int = Field(default=0, ge=0, le=100000)
    max_blocked_members: int = Field(default=0, ge=0, le=100000)
    max_weighted_posture_score: float = Field(default=40.0, ge=0.0, le=100.0)
    max_risk_concentration_percent: float = Field(default=100.0, ge=0.0, le=100.0)
    max_overdue_findings: int = Field(default=0, ge=0, le=100000)
    max_accepted_risk_findings: int = Field(default=0, ge=0, le=100000)
    max_missed_objectives: int = Field(default=0, ge=0, le=100000)
    max_off_track_forecasts: int = Field(default=0, ge=0, le=100000)
    require_all_release_gates_passed: bool = True
    require_all_policies_passed: bool = True
    require_all_governance_passed: bool = True


class PortfolioGovernanceProfileResponse(BaseModel):
    profile_id: str
    portfolio_id: str
    version: int
    source: Literal["built_in", "declared"]
    governance_sha256: str
    document: PortfolioGovernanceDocument
    created_at: datetime | None = None
    latest: bool = False


class PortfolioGovernanceStatus(BaseModel):
    portfolio_id: str
    latest_profile: PortfolioGovernanceProfileResponse
    versions: list[PortfolioGovernanceProfileResponse]


class PortfolioMemberInput(BaseModel):
    root_scan_id: str
    pinned_scan_id: str | None = None
    display_name: str = Field(min_length=1, max_length=180)
    business_unit: str | None = Field(default=None, max_length=180)
    criticality: Criticality = "medium"


class PortfolioCreate(BaseModel):
    name: str = Field(min_length=1, max_length=180)
    description: str | None = Field(default=None, max_length=4000)
    governance: PortfolioGovernanceDocument | None = None
    members: list[PortfolioMemberInput] = Field(default_factory=list, max_length=500)


class PortfolioUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=180)
    description: str | None = Field(default=None, max_length=4000)


class PortfolioMemberResponse(PortfolioMemberInput):
    added_at: datetime | None = None


class PortfolioResponse(BaseModel):
    portfolio_id: str
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime
    members: list[PortfolioMemberResponse] = Field(default_factory=list)


class PortfolioCheck(BaseModel):
    key: str
    label: str
    operator: Literal["<=", "=="]
    target: float | int | bool
    actual: float | int | bool
    status: CheckStatus
    explanation: str


class PortfolioMemberSnapshot(BaseModel):
    root_scan_id: str
    scan_id: str | None
    display_name: str
    business_unit: str | None
    criticality: Criticality
    weight: int
    pinned: bool
    branch_heads: int
    scan_status: str | None
    evidence_state: EvidenceState
    evidence_age_days: float | None = None
    readiness: MemberReadiness
    reasons: list[str] = Field(default_factory=list)
    posture_score: float | None = None
    posture_state: str | None = None
    residual_risk_total: float | None = None
    confirmed_findings: int | None = None
    policy_blockers: int | None = None
    accepted_risk_findings: int | None = None
    sla_at_risk: int | None = None
    sla_overdue: int | None = None
    release_gate_state: str | None = None
    policy_state: str | None = None
    governance_state: str | None = None
    objective_state: str | None = None
    forecast_status: str | None = None
    forecast_confidence: str | None = None
    projected_active_findings: float | None = None
    objective_target_date: datetime | None = None


class RiskConcentration(BaseModel):
    root_scan_id: str
    display_name: str
    weighted_residual_risk: float
    share_percent: float


class PortfolioSummary(BaseModel):
    state: PortfolioState
    total_members: int
    passed_members: int
    at_risk_members: int
    blocked_members: int
    current_members: int
    stale_members: int
    missing_members: int
    unavailable_members: int
    ambiguous_heads: int
    confirmed_findings: int
    policy_blockers: int
    accepted_risk_findings: int
    sla_at_risk: int
    sla_overdue: int
    missed_objectives: int
    at_risk_objectives: int
    off_track_forecasts: int
    insufficient_forecasts: int
    weighted_posture_score: float | None
    weighted_residual_risk: float
    top_risk_concentration_percent: float
    reasons: list[str] = Field(default_factory=list)


class PortfolioDashboard(BaseModel):
    schema_version: str = "sentinel-portfolio-dashboard-v1"
    engine_version: str
    generated_at: datetime
    portfolio: PortfolioResponse
    governance: PortfolioGovernanceProfileResponse
    summary: PortfolioSummary
    checks: list[PortfolioCheck]
    concentrations: list[RiskConcentration]
    members: list[PortfolioMemberSnapshot]


class PortfolioIntegrity(BaseModel):
    algorithm: str = "sha256"
    canonicalization: str = "json-sort-keys-utf8-v1"
    section_sha256: dict[str, str]
    payload_sha256: str


class PortfolioEvidenceBundle(BaseModel):
    bundle_type: str = "sentinel-portfolio-evidence"
    schema_version: str = "sentinel-portfolio-evidence-v1"
    generated_at: datetime
    versions: dict[str, str]
    portfolio: PortfolioResponse
    governance: PortfolioGovernanceProfileResponse
    summary: PortfolioSummary
    checks: list[PortfolioCheck]
    concentrations: list[RiskConcentration]
    members: list[PortfolioMemberSnapshot]
    integrity: PortfolioIntegrity
