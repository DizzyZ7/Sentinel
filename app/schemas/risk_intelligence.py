from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.policy import GateResponse

Priority = Literal["immediate", "before_release", "planned", "monitor"]


class RiskFactorScores(BaseModel):
    technical: float
    exploitability: float
    exposure: float
    asset_importance: float
    confidence: float
    remediation_multiplier: float


class RiskIntelligenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    engine_version: str
    asset_name: str
    asset_type: str
    component: str
    attack_surface: str
    exposure: str
    data_exposure: str
    privilege_required: str
    blast_radius: str
    technical_score: float
    exploitability_score: float
    exposure_score: float
    asset_importance_score: float
    confidence_score: float
    inherent_risk_score: float
    residual_risk_score: float
    priority: Priority
    impact_summary: str
    business_impact: str
    recommended_action: str
    remediation_plan: list[str]
    estimated_effort: str
    scoring_factors: dict
    context_profile_version: int | None = None
    context_sha256: str | None = None
    context_source: str = "heuristic"
    context_asset_id: str | None = None
    context_project_name: str | None = None
    created_at: datetime | None = None


class ExecutiveRiskItem(BaseModel):
    finding_id: str
    title: str
    rule_id: str
    file_path: str
    line: int
    severity: str
    risk: RiskIntelligenceResponse


class ExecutiveSummary(BaseModel):
    posture_score: float
    posture_state: Literal["critical", "high", "elevated", "guarded", "clear"]
    confirmed_findings: int
    unreviewed_candidates: int
    immediate_actions: int
    before_release_actions: int
    public_exposures: int
    sensitive_data_paths: int
    affected_assets: int
    top_attack_surface: str | None
    release_recommendation: str


class ExecutiveContextSummary(BaseModel):
    project_name: str | None = None
    environment: str = "unknown"
    profile_version: int | None = None
    context_sha256: str | None = None
    source: str = "heuristic"
    declared_assets: int = 0
    matched_assets: int = 0
    compliance_frameworks: list[str] = Field(default_factory=list)


class ExecutiveReport(BaseModel):
    schema_version: str = "sentinel-executive-risk-v2"
    scan_id: str
    generated_at: datetime
    engine_version: str
    context: ExecutiveContextSummary
    gate: GateResponse
    summary: ExecutiveSummary
    top_risks: list[ExecutiveRiskItem]
    risks: list[ExecutiveRiskItem]
    attack_surfaces: dict[str, int]
    assets: dict[str, int]
