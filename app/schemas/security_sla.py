from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Severity = Literal["low", "medium", "high", "critical"]
SLAProfileSource = Literal["inferred", "declared", "built_in", "preview"]
SLAState = Literal["on_track", "at_risk", "overdue"]
Exposure = Literal["unknown", "internal", "partner", "public"]
DataClassification = Literal["public", "internal", "confidential", "restricted"]
Criticality = Literal["low", "medium", "high", "critical"]
Environment = Literal["unknown", "development", "staging", "production"]


class SecuritySLAOverride(BaseModel):
    override_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    name: str = Field(min_length=1, max_length=180)
    enabled: bool = True
    asset_ids: list[str] = Field(default_factory=list, max_length=50)
    rule_ids: list[str] = Field(default_factory=list, max_length=50)
    path_patterns: list[str] = Field(default_factory=list, max_length=30)
    severities: list[Severity] = Field(default_factory=list)
    exposures: list[Exposure] = Field(default_factory=list)
    data_classifications: list[DataClassification] = Field(default_factory=list)
    criticalities: list[Criticality] = Field(default_factory=list)
    environments: list[Environment] = Field(default_factory=list)
    due_hours: int | None = Field(default=None, ge=1, le=8760)
    assigned_team: str | None = Field(default=None, min_length=1, max_length=180)
    risk_owner: str | None = Field(default=None, min_length=1, max_length=180)
    escalation_contact: str | None = Field(default=None, min_length=1, max_length=180)

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


class SecuritySLADocument(BaseModel):
    profile_name: str = Field(default="Sentinel default remediation SLA", min_length=1, max_length=180)
    critical_hours: int = Field(default=24, ge=1, le=8760)
    high_hours: int = Field(default=168, ge=1, le=8760)
    medium_hours: int = Field(default=720, ge=1, le=17520)
    low_hours: int = Field(default=2160, ge=1, le=35040)
    production_multiplier: float = Field(default=0.75, ge=0.1, le=1.0)
    public_asset_multiplier: float = Field(default=0.5, ge=0.1, le=1.0)
    restricted_data_multiplier: float = Field(default=0.5, ge=0.1, le=1.0)
    critical_asset_multiplier: float = Field(default=0.5, ge=0.1, le=1.0)
    at_risk_window_hours: int = Field(default=48, ge=1, le=2160)
    default_team: str = Field(default="Unassigned security team", min_length=1, max_length=180)
    default_risk_owner: str = Field(default="Unassigned risk owner", min_length=1, max_length=180)
    default_escalation_contact: str | None = Field(default=None, max_length=180)
    overrides: list[SecuritySLAOverride] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_order_and_ids(self):
        if not (self.critical_hours <= self.high_hours <= self.medium_hours <= self.low_hours):
            raise ValueError("SLA hours must increase from critical through low severity")
        ids = [item.override_id for item in self.overrides]
        if len(ids) != len(set(ids)):
            raise ValueError("SLA override IDs must be unique")
        return self


class SecuritySLAProfileResponse(BaseModel):
    profile_id: str
    root_scan_id: str
    version: int
    source: SLAProfileSource
    sla_sha256: str
    document: SecuritySLADocument
    created_at: datetime | None = None
    assigned_to_current_scan: bool = False


class SecuritySLAStatus(BaseModel):
    scan_id: str
    root_scan_id: str
    assigned_profile: SecuritySLAProfileResponse
    latest_profile: SecuritySLAProfileResponse
    versions: list[SecuritySLAProfileResponse]
    next_rescan_uses_version: int


class FindingSLAResponse(BaseModel):
    finding_id: str
    fingerprint: str
    rule_id: str
    title: str
    file_path: str
    line: int
    severity: str
    asset_id: str | None
    assigned_team: str
    risk_owner: str
    escalation_contact: str | None
    assignment_source: str
    matched_override_id: str | None
    profile_version: int
    profile_sha256: str
    started_at: datetime
    at_risk_at: datetime
    due_at: datetime
    age_hours: float
    remaining_hours: float
    state: SLAState
    accepted_risk: bool = False
    exception_id: str | None = None
    exception_expires_at: datetime | None = None
    exception_outlives_sla: bool = False
    sla_blocker: bool = False


class TeamDebtSummary(BaseModel):
    team: str
    total: int
    on_track: int
    at_risk: int
    overdue: int
    accepted_risk: int


class SecurityDebtSummary(BaseModel):
    total: int
    on_track: int
    at_risk: int
    overdue: int
    accepted_risk: int
    unassigned: int
    due_within_7_days: int
    oldest_age_hours: float
    sla_blockers: int


class SecurityDebtDashboard(BaseModel):
    scan_id: str
    generated_at: datetime
    state: Literal["passed", "at_risk", "accepted_risk", "blocked"]
    release_permitted: bool
    profile_version: int
    profile_sha256: str
    profile_name: str
    summary: SecurityDebtSummary
    teams: list[TeamDebtSummary]
    findings: list[FindingSLAResponse]


class SecuritySLAPreview(BaseModel):
    scan_id: str
    source: Literal["preview"] = "preview"
    sla_sha256: str
    dashboard: SecurityDebtDashboard


class SecurityDebtComparisonSummary(BaseModel):
    baseline_total: int
    current_total: int
    introduced: int
    resolved: int
    persistent: int
    newly_overdue: int
    recovered_from_overdue: int
    owner_changed: int
    release_state_changed: bool


class SecurityDebtComparison(BaseModel):
    baseline_scan_id: str
    current_scan_id: str
    summary: SecurityDebtComparisonSummary
    introduced: list[FindingSLAResponse]
    resolved: list[FindingSLAResponse]
    persistent: list[FindingSLAResponse]
    baseline: SecurityDebtDashboard
    current: SecurityDebtDashboard
