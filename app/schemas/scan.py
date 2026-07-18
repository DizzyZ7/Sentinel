from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.schemas.finding import FindingResponse
from app.schemas.progress import ScanProgress


class ScanCreated(BaseModel):
    scan_id: str
    status: str
    status_url: str
    report_url: str


class ScanStatus(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    source_type: str
    source_url: str | None
    original_filename: str | None
    file_count: int
    candidate_count: int
    finding_count: int
    risk_score: float
    error: str | None
    created_at: datetime
    completed_at: datetime | None
    progress: ScanProgress | None = None


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ReportResponse(ScanStatus):
    severity_summary: SeveritySummary
    findings: list[FindingResponse]
    structure: list[dict]
