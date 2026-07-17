from typing import Literal

from pydantic import BaseModel

GateState = Literal["passed", "blocked"]


class GateBlocker(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    file_path: str
    line: int
    severity: str | None
    reason: str


class GateResponse(BaseModel):
    scan_id: str
    state: GateState
    passed: bool
    block_on: Literal["critical", "high", "medium", "low"]
    fail_closed_on_unreviewed: bool
    evaluated_findings: int
    remediated_findings: int
    blockers: list[GateBlocker]
