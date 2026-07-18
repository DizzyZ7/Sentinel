from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.security_policy import SecurityPolicyCompliance

ExceptionTargetType = Literal["finding", "rule", "asset"]
ExceptionScopeType = Literal["fingerprint", "rule", "asset"]
ExceptionStatus = Literal["pending", "approved", "rejected", "revoked", "expired"]
ExceptionDecision = Literal["approved", "rejected"]
ExceptionMaximumSeverity = Literal["low", "medium", "high"]
GovernanceState = Literal["passed", "accepted_risk", "blocked"]


class RiskExceptionCreate(BaseModel):
    target_type: ExceptionTargetType
    target_value: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=3, max_length=180)
    justification: str = Field(min_length=20, max_length=4000)
    risk_owner: str = Field(min_length=2, max_length=180)
    requested_by: str = Field(min_length=2, max_length=180)
    maximum_severity: ExceptionMaximumSeverity = "high"
    expires_at: datetime

    @field_validator("target_value", "title", "justification", "risk_owner", "requested_by")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class RiskExceptionDecisionRequest(BaseModel):
    decision: ExceptionDecision
    actor: str = Field(min_length=2, max_length=180)
    reason: str = Field(min_length=10, max_length=2000)

    @field_validator("actor", "reason")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class RiskExceptionRevokeRequest(BaseModel):
    actor: str = Field(min_length=2, max_length=180)
    reason: str = Field(min_length=10, max_length=2000)

    @field_validator("actor", "reason")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class RiskExceptionRenewRequest(BaseModel):
    actor: str = Field(min_length=2, max_length=180)
    reason: str = Field(min_length=20, max_length=2000)
    expires_at: datetime

    @field_validator("actor", "reason")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class RiskExceptionEventResponse(BaseModel):
    id: str
    event_type: str
    actor: str
    reason: str
    metadata: dict = Field(default_factory=dict)
    created_at: datetime | None = None


class RiskExceptionResponse(BaseModel):
    id: str
    root_scan_id: str
    created_scan_id: str
    scope_type: ExceptionScopeType
    scope_value: str
    target_label: str
    title: str
    justification: str
    risk_owner: str
    requested_by: str
    maximum_severity: ExceptionMaximumSeverity
    expires_at: datetime
    status: ExceptionStatus
    active: bool
    decision_by: str | None = None
    decision_reason: str | None = None
    decided_at: datetime | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None
    revoked_at: datetime | None = None
    created_at: datetime | None = None
    events: list[RiskExceptionEventResponse] = Field(default_factory=list)


class RiskExceptionList(BaseModel):
    scan_id: str
    root_scan_id: str
    generated_at: datetime
    pending: int
    active: int
    expired: int
    rejected_or_revoked: int
    exceptions: list[RiskExceptionResponse]


class ExceptionAwareFindingResult(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    file_path: str
    line: int
    severity: str | None
    raw_blocker_reasons: list[str]
    disposition: Literal["passed", "accepted_risk", "blocked"]
    exception_id: str | None = None
    exception_scope: str | None = None
    exception_expires_at: datetime | None = None
    non_waivable_reason: str | None = None


class ExceptionGovernanceSummary(BaseModel):
    evaluated_findings: int
    raw_blocking_findings: int
    accepted_risk_findings: int
    unwaived_blocking_findings: int
    active_exceptions: int
    pending_exceptions: int
    expired_exceptions: int
    expiring_within_7_days: int


class ExceptionAwareCompliance(BaseModel):
    schema_version: str = "sentinel-exception-governance-v1"
    scan_id: str
    generated_at: datetime
    state: GovernanceState
    release_permitted: bool
    raw_policy_compliance: SecurityPolicyCompliance
    summary: ExceptionGovernanceSummary
    results: list[ExceptionAwareFindingResult]


class ExceptionDebtItem(BaseModel):
    scope_key: str
    scope_type: ExceptionScopeType
    scope_value: str
    exception_id: str
    title: str
    risk_owner: str
    maximum_severity: ExceptionMaximumSeverity
    expires_at: datetime


class ExceptionDebtComparisonSummary(BaseModel):
    baseline_active_scopes: int
    current_active_scopes: int
    introduced: int
    resolved: int
    persistent: int
    baseline_accepted_findings: int
    current_accepted_findings: int
    governance_state_changed: bool


class ExceptionDebtComparison(BaseModel):
    schema_version: str = "sentinel-exception-debt-v1"
    baseline_scan_id: str
    current_scan_id: str
    baseline_as_of: datetime
    current_as_of: datetime
    summary: ExceptionDebtComparisonSummary
    introduced: list[ExceptionDebtItem]
    resolved: list[ExceptionDebtItem]
    persistent: list[ExceptionDebtItem]
    baseline: ExceptionAwareCompliance
    current: ExceptionAwareCompliance


class RiskExceptionImport(BaseModel):
    exceptions: list[RiskExceptionCreate] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def unique_targets(self):
        keys = [(item.target_type, item.target_value) for item in self.exceptions]
        if len(keys) != len(set(keys)):
            raise ValueError("Imported exception targets must be unique")
        return self
