from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

VerificationStatus = Literal["passed", "failed", "inconclusive", "skipped"]
CheckStatus = Literal["passed", "failed", "inconclusive"]


class VerificationCheck(BaseModel):
    name: str
    status: CheckStatus
    detail: str


class RegressionVerificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    status: VerificationStatus
    mode: str
    verifier_version: str
    before_detected: bool | None
    after_detected: bool | None
    patch_applied: bool
    source_executed: bool
    before_digest: str | None
    after_digest: str | None
    checks: list[VerificationCheck]
    error: str | None
    verified_at: datetime


class VerificationSummary(BaseModel):
    total: int
    passed: int
    failed: int
    inconclusive: int
    skipped: int


class ScanVerificationResponse(BaseModel):
    scan_id: str
    summary: VerificationSummary
    verifications: list[RegressionVerificationResponse]
