from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

TrendDirection = Literal["improving", "stable", "worsening", "insufficient_history"]
PostureState = Literal["critical", "high", "elevated", "guarded", "clear"]
GateState = Literal["passed", "blocked"]
GovernanceState = Literal["passed", "accepted_risk", "blocked"]
SLAState = Literal["passed", "at_risk", "accepted_risk", "blocked"]


class SecurityPostureDelta(BaseModel):
    introduced: int = 0
    resolved: int = 0
    changed: int = 0
    persistent: int = 0
    reopened: int = 0


class SecurityPosturePoint(BaseModel):
    scan_id: str
    parent_scan_id: str | None
    root_scan_id: str
    generation: int
    created_at: datetime
    completed_at: datetime | None
    candidate_count: int
    confirmed_findings: int
    dismissed_candidates: int
    unreviewed_candidates: int
    verified_remediations: int
    release_gate_state: GateState
    policy_state: GateState
    governance_state: GovernanceState
    sla_state: SLAState
    policy_blockers: int
    accepted_risk_findings: int
    sla_at_risk: int
    sla_overdue: int
    posture_score: float
    posture_state: PostureState
    residual_risk_total: float
    residual_risk_average: float
    residual_risk_max: float
    delta: SecurityPostureDelta
    direction: TrendDirection


class RemediationEpisode(BaseModel):
    fingerprint: str
    rule_id: str
    title: str
    file_path: str
    first_seen_scan_id: str
    first_seen_at: datetime
    resolved_scan_id: str
    resolved_at: datetime
    resolution_hours: float
    due_at: datetime | None = None
    resolved_within_sla: bool | None = None


class RecurrenceItem(BaseModel):
    fingerprint: str
    rule_id: str
    title: str
    file_path: str
    first_seen_scan_id: str
    first_seen_at: datetime
    last_reopened_scan_id: str
    last_reopened_at: datetime
    recurrence_count: int
    current_active: bool


class RemediationEffectiveness(BaseModel):
    resolution_events: int
    reopened_events: int
    recurrence_rate: float
    mean_resolution_hours: float | None
    median_resolution_hours: float | None
    resolved_within_sla: int
    resolved_after_sla: int
    sla_attainment_rate: float | None
    currently_active_fingerprints: int
    currently_resolved_fingerprints: int
    episodes: list[RemediationEpisode] = Field(default_factory=list)
    recurrences: list[RecurrenceItem] = Field(default_factory=list)


class SecurityPostureTrendSummary(BaseModel):
    generations: int
    trend_direction: TrendDirection
    current_posture_score: float
    current_posture_state: PostureState
    current_release_gate_state: GateState
    current_governance_state: GovernanceState
    current_sla_state: SLAState
    confirmed_delta: int
    posture_score_delta: float
    policy_blocker_delta: int
    overdue_delta: int
    total_introduced: int
    total_resolved: int
    total_changed: int
    total_reopened: int


class SecurityPostureTrend(BaseModel):
    schema_version: str = "sentinel-security-posture-v1"
    engine_version: str
    generated_at: datetime
    root_scan_id: str
    current_scan_id: str
    summary: SecurityPostureTrendSummary
    remediation: RemediationEffectiveness
    points: list[SecurityPosturePoint]
