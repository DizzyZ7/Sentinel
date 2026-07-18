from typing import Literal

from pydantic import BaseModel

NodeStage = Literal["source", "triage", "sink", "verdict", "patch", "verification", "human"]
NodeStatus = Literal["danger", "warning", "neutral", "safe", "blocked"]
PathStatus = Literal[
    "dismissed",
    "exposed",
    "patch_ready",
    "verified",
    "approved",
    "rejected",
    "unreviewed",
]


class AttackPathNode(BaseModel):
    id: str
    stage: NodeStage
    label: str
    detail: str
    status: NodeStatus


class AttackPathEdge(BaseModel):
    source: str
    target: str
    label: str


class AttackPath(BaseModel):
    id: str
    finding_id: str
    title: str
    rule_id: str
    file_path: str
    line: int
    severity: str | None
    status: PathStatus
    attack_surface: str
    nodes: list[AttackPathNode]
    edges: list[AttackPathEdge]


class AttackPathSummary(BaseModel):
    total: int
    exposed: int
    patch_ready: int
    verified: int
    approved: int
    rejected: int
    dismissed: int
    unreviewed: int


class AttackPathResponse(BaseModel):
    scan_id: str
    summary: AttackPathSummary
    paths: list[AttackPath]
