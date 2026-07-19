from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

ObjectiveSource = Literal["inferred", "declared", "built_in", "preview"]
ObjectiveCheckStatus = Literal["met", "missed", "not_measurable"]
ObjectiveState = Literal["met", "at_risk", "missed", "insufficient_history"]
DeadlineState = Literal["future", "due", "past"]
ForecastStatus = Literal["met", "on_track", "at_risk", "off_track", "missed", "insufficient_history"]
ForecastConfidence = Literal["insufficient_history", "low", "medium", "high"]
MetricValue = float | int | str | bool | None


class SecurityObjectiveDocument(BaseModel):
    objective_name: str = Field(default="Sentinel baseline security objectives", min_length=1, max_length=180)
    target_date: datetime
    max_posture_score: float = Field(default=40.0, ge=0.0, le=100.0)
    max_confirmed_findings: int = Field(default=0, ge=0, le=100000)
    max_policy_blockers: int = Field(default=0, ge=0, le=100000)
    max_overdue_findings: int = Field(default=0, ge=0, le=100000)
    max_accepted_risk_findings: int = Field(default=0, ge=0, le=100000)
    min_sla_attainment_rate: float = Field(default=90.0, ge=0.0, le=100.0)
    max_mean_resolution_hours: float = Field(default=168.0, ge=0.0, le=87600.0)
    max_recurrence_rate: float = Field(default=10.0, ge=0.0, le=100.0)
    require_release_gate_passed: bool = True
    require_policy_passed: bool = True
    require_governance_passed: bool = True
    require_measurable_history: bool = False
    minimum_forecast_confidence: Literal["low", "medium", "high"] = "low"

    @field_validator("target_date")
    @classmethod
    def normalize_target_date(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Objective target_date must include a timezone")
        normalized = value.astimezone(UTC)
        if normalized.year < 2000 or normalized.year > 2200:
            raise ValueError("Objective target_date must be between years 2000 and 2200")
        return normalized


class SecurityObjectiveProfileResponse(BaseModel):
    profile_id: str
    root_scan_id: str
    version: int
    source: ObjectiveSource
    objective_sha256: str
    document: SecurityObjectiveDocument
    created_at: datetime | None = None
    assigned_to_current_scan: bool = False


class SecurityObjectiveStatus(BaseModel):
    scan_id: str
    root_scan_id: str
    assigned_profile: SecurityObjectiveProfileResponse
    latest_profile: SecurityObjectiveProfileResponse
    versions: list[SecurityObjectiveProfileResponse]
    next_rescan_uses_version: int


class ObjectiveCheck(BaseModel):
    key: str
    label: str
    operator: Literal["<=", ">=", "=="]
    target: MetricValue
    actual: MetricValue
    status: ObjectiveCheckStatus
    source: str
    explanation: str


class SecurityObjectiveEvaluationSummary(BaseModel):
    total_checks: int
    met_checks: int
    missed_checks: int
    not_measurable_checks: int


class SecurityObjectiveEvaluation(BaseModel):
    schema_version: str = "sentinel-security-objective-evaluation-v1"
    state: ObjectiveState
    met: bool
    as_of: datetime
    target_date: datetime
    deadline_state: DeadlineState
    days_remaining: float
    summary: SecurityObjectiveEvaluationSummary
    checks: list[ObjectiveCheck]


class ForecastInterval(BaseModel):
    baseline_scan_id: str
    current_scan_id: str
    elapsed_days: float
    introduced: int
    reopened: int
    resolved: int
    inflow_rate_per_day: float
    resolution_rate_per_day: float


class RemediationForecast(BaseModel):
    schema_version: str = "sentinel-remediation-forecast-v1"
    status: ForecastStatus
    confidence: ForecastConfidence
    as_of: datetime
    target_date: datetime
    horizon_days: float
    history_generations: int
    history_intervals: int
    history_days: float
    current_active_findings: int
    target_active_findings: int
    introduction_rate_per_day: float | None
    resolution_rate_per_day: float | None
    net_burn_rate_per_day: float | None
    required_resolution_rate_per_day: float | None
    projected_active_findings: float | None
    projected_net_change: float | None
    projected_clear_date: datetime | None
    confidence_reasons: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    intervals: list[ForecastInterval] = Field(default_factory=list)


class SecurityObjectiveReport(BaseModel):
    schema_version: str = "sentinel-security-objective-report-v1"
    objective_engine_version: str
    forecast_engine_version: str
    generated_at: datetime
    scan_id: str
    root_scan_id: str
    objective_profile_id: str
    objective_version: int
    objective_sha256: str
    objective_name: str
    evaluation: SecurityObjectiveEvaluation
    forecast: RemediationForecast


class SecurityObjectivePreview(BaseModel):
    scan_id: str
    source: Literal["preview"] = "preview"
    objective_sha256: str
    report: SecurityObjectiveReport
