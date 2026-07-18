from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas.comparison import ComparisonSummary, DeltaGateBlocker


class LineageNode(BaseModel):
    scan_id: str
    parent_scan_id: str | None
    root_scan_id: str
    generation: int
    status: str
    source_type: str
    source_label: str
    created_at: datetime
    completed_at: datetime | None
    risk_score: float
    finding_count: int
    candidate_count: int
    is_current: bool
    eligible_baseline: bool


class LineageResponse(BaseModel):
    schema_version: str = "sentinel-lineage-v1"
    current_scan_id: str
    root_scan_id: str
    parent_scan_id: str | None
    default_baseline_scan_id: str | None
    nodes: list[LineageNode]


class CIGateResponse(BaseModel):
    schema_version: str = "sentinel-ci-gate-v1"
    current_scan_id: str
    baseline_scan_id: str
    state: Literal["passed", "blocked"]
    passed: bool
    exit_code: Literal[0, 1]
    block_on: Literal["critical", "high", "medium", "low"]
    fail_closed_on_unreviewed: bool
    summary: ComparisonSummary
    blockers: list[DeltaGateBlocker]
    comparison_url: str
