from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.policy import GateResponse

DeltaState = Literal["introduced", "resolved", "persistent", "changed"]
SeverityDirection = Literal["increased", "decreased", "unchanged", "unknown"]


class ComparisonFinding(BaseModel):
    id: str
    fingerprint: str
    rule_id: str
    title: str
    file_path: str
    line: int
    end_line: int
    language: str
    confirmed: bool | None
    severity: str | None
    static_confidence: float
    llm_status: str
    patch_valid: bool | None
    verification_status: str | None
    decision: str | None


class ComparisonItem(BaseModel):
    state: DeltaState
    locator: str
    severity_direction: SeverityDirection
    baseline: ComparisonFinding | None
    current: ComparisonFinding | None


class ComparisonSummary(BaseModel):
    introduced: int
    resolved: int
    persistent: int
    changed: int
    blocking_regressions: int
    baseline_risk_score: float
    current_risk_score: float
    risk_delta: float


class DeltaGateBlocker(BaseModel):
    state: Literal["introduced", "changed"]
    current_finding_id: str
    baseline_finding_id: str | None
    rule_id: str
    title: str
    file_path: str
    line: int
    severity: str | None
    reason: str


class DeltaGateResponse(BaseModel):
    baseline_scan_id: str
    current_scan_id: str
    state: Literal["passed", "blocked"]
    passed: bool
    block_on: Literal["critical", "high", "medium", "low"]
    fail_closed_on_unreviewed: bool
    evaluated_regressions: int
    blockers: list[DeltaGateBlocker]


class ScanComparison(BaseModel):
    schema_version: str = "sentinel-scan-comparison-v1"
    generated_at: datetime
    baseline_scan_id: str
    current_scan_id: str
    baseline_gate: GateResponse
    current_gate: GateResponse
    delta_gate: DeltaGateResponse
    summary: ComparisonSummary
    items: list[ComparisonItem]


class RescanCreated(BaseModel):
    scan_id: str
    baseline_scan_id: str
    status: str
    status_url: str
    report_url: str
    comparison_url: str
