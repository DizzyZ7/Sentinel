from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.portfolio import PortfolioDashboard, PortfolioState

SnapshotSource = Literal["manual", "scheduled", "api"]
TransitionDirection = Literal["initial", "improved", "unchanged", "degraded"]
ScheduleState = Literal["never_captured", "current", "due", "overdue"]
AlertSeverity = Literal["info", "warning", "high", "critical"]
AlertStatus = Literal["open", "acknowledged", "resolved"]


class PortfolioControlDocument(BaseModel):
    profile_name: str = Field(default="Sentinel continuous control plane", min_length=1, max_length=180)
    snapshot_interval_hours: int = Field(default=24, ge=1, le=8760)
    alert_on_at_risk: bool = True
    alert_on_blocked: bool = True
    alert_on_insufficient_evidence: bool = True
    alert_on_state_regression: bool = True
    alert_on_recovery: bool = False
    alert_on_member_blocked: bool = True
    alert_on_evidence_degradation: bool = True
    alert_on_sla_overdue: bool = True
    alert_on_objective_missed: bool = True
    alert_on_forecast_off_track: bool = True
    alert_on_governance_miss: bool = True
    auto_resolve_cleared_alerts: bool = True
    route_labels: list[str] = Field(default_factory=lambda: ["local-security-queue"], min_length=1, max_length=20)

    @field_validator("route_labels")
    @classmethod
    def normalize_routes(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in value:
            route = item.strip()
            if not route:
                raise ValueError("route labels cannot be blank")
            if len(route) > 120:
                raise ValueError("route labels must be at most 120 characters")
            if route not in normalized:
                normalized.append(route)
        return normalized


class PortfolioControlProfileResponse(BaseModel):
    profile_id: str
    portfolio_id: str
    version: int
    source: Literal["built_in", "declared"]
    profile_sha256: str
    document: PortfolioControlDocument
    created_at: datetime | None = None
    latest: bool = False


class PortfolioControlStatus(BaseModel):
    portfolio_id: str
    latest_profile: PortfolioControlProfileResponse
    versions: list[PortfolioControlProfileResponse]


class SnapshotCaptureRequest(BaseModel):
    source: SnapshotSource = "manual"
    actor: str = Field(default="local-operator", min_length=1, max_length=180)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=180)


class PortfolioMemberTransition(BaseModel):
    root_scan_id: str
    display_name: str
    change_type: Literal["added", "removed", "changed"]
    previous_readiness: str | None = None
    current_readiness: str | None = None
    previous_evidence_state: str | None = None
    current_evidence_state: str | None = None
    changes: list[str] = Field(default_factory=list)


class PortfolioSnapshotTransition(BaseModel):
    from_snapshot_id: str | None = None
    from_state: PortfolioState | None = None
    to_state: PortfolioState
    direction: TransitionDirection
    changed: bool
    summary_deltas: dict[str, float] = Field(default_factory=dict)
    member_transitions: list[PortfolioMemberTransition] = Field(default_factory=list)
    newly_missed_checks: list[str] = Field(default_factory=list)
    cleared_checks: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class PortfolioSnapshotSummary(BaseModel):
    snapshot_id: str
    portfolio_id: str
    sequence: int
    source: SnapshotSource
    actor: str
    idempotency_key: str | None = None
    captured_at: datetime
    state: PortfolioState
    previous_snapshot_id: str | None = None
    previous_snapshot_sha256: str | None = None
    dashboard_sha256: str
    snapshot_sha256: str
    governance_profile_id: str
    governance_version: int
    governance_sha256: str
    control_profile_id: str
    control_profile_version: int
    control_profile_sha256: str
    transition: PortfolioSnapshotTransition


class PortfolioSnapshotDetail(PortfolioSnapshotSummary):
    dashboard: PortfolioDashboard


class PortfolioSnapshotCaptureResult(BaseModel):
    created: bool
    snapshot: PortfolioSnapshotDetail
    alerts_opened: int = 0
    alerts_reopened: int = 0
    alerts_auto_resolved: int = 0


class PortfolioAlertResponse(BaseModel):
    alert_id: str
    portfolio_id: str
    condition_key: str
    rule_key: str
    first_snapshot_id: str | None
    last_seen_snapshot_id: str | None
    severity: AlertSeverity
    title: str
    detail: str
    route_labels: list[str]
    status: AlertStatus
    occurrence_count: int
    created_at: datetime | None = None
    updated_at: datetime | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    resolved_at: datetime | None = None
    resolution_reason: str | None = None


class AlertAcknowledgeRequest(BaseModel):
    actor: str = Field(default="local-operator", min_length=1, max_length=180)


class AlertResolveRequest(BaseModel):
    actor: str = Field(default="local-operator", min_length=1, max_length=180)
    reason: str = Field(min_length=1, max_length=2000)


class PortfolioAuditEventResponse(BaseModel):
    event_id: str
    portfolio_id: str
    sequence: int
    event_type: str
    actor: str
    occurred_at: datetime
    snapshot_id: str | None = None
    alert_id: str | None = None
    payload: dict
    previous_event_sha256: str | None = None
    event_sha256: str


class PortfolioControlPlaneSchedule(BaseModel):
    portfolio_id: str
    schedule_state: ScheduleState
    caller_driven: bool = True
    snapshot_interval_hours: int
    latest_snapshot_id: str | None = None
    latest_snapshot_state: PortfolioState | None = None
    latest_snapshot_at: datetime | None = None
    next_due_at: datetime | None = None
    age_hours: float | None = None
    configuration_changed_since_snapshot: bool
    open_alerts: int
    acknowledged_alerts: int
    resolved_alerts: int
    reasons: list[str] = Field(default_factory=list)


class ControlPlaneChainVerification(BaseModel):
    snapshot_chain_valid: bool
    audit_chain_valid: bool
    snapshot_count: int
    audit_event_count: int
    failures: list[str] = Field(default_factory=list)


class PortfolioControlPlaneTimeline(BaseModel):
    schema_version: str = "sentinel-control-plane-timeline-v1"
    generated_at: datetime
    portfolio_id: str
    control: PortfolioControlStatus
    schedule: PortfolioControlPlaneSchedule
    chain: ControlPlaneChainVerification
    snapshots: list[PortfolioSnapshotSummary]
    alerts: list[PortfolioAlertResponse]
    audit_events: list[PortfolioAuditEventResponse]


class ControlPlaneIntegrity(BaseModel):
    algorithm: str = "sha256"
    canonicalization: str = "json-sort-keys-utf8-v1"
    section_sha256: dict[str, str]
    payload_sha256: str


class PortfolioControlPlaneEvidence(BaseModel):
    bundle_type: str = "sentinel-control-plane-evidence"
    schema_version: str = "sentinel-control-plane-evidence-v1"
    generated_at: datetime
    versions: dict[str, str]
    portfolio_id: str
    control: PortfolioControlStatus
    schedule: PortfolioControlPlaneSchedule
    chain: ControlPlaneChainVerification
    snapshots: list[PortfolioSnapshotDetail]
    alerts: list[PortfolioAlertResponse]
    audit_events: list[PortfolioAuditEventResponse]
    integrity: ControlPlaneIntegrity
