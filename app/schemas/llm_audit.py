from datetime import datetime

from pydantic import BaseModel, ConfigDict


class LLMReviewRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    status: str
    model: str
    response_id: str | None
    prompt_version: str
    schema_version: str
    context_sha256: str | None
    redaction_count: int
    redaction_summary: dict
    retry_count: int
    latency_ms: int | None
    input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    error: str | None
    started_at: datetime
    completed_at: datetime | None


class LLMAuditSummary(BaseModel):
    total: int
    completed: int
    failed: int
    skipped: int
    redactions: int
    input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    total_latency_ms: int


class ScanLLMAuditResponse(BaseModel):
    scan_id: str
    summary: LLMAuditSummary
    reviews: list[LLMReviewRunResponse]
