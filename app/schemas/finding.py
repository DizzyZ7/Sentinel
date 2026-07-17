from pydantic import BaseModel, ConfigDict


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str
    title: str
    file_path: str
    line: int
    end_line: int
    language: str
    snippet: str
    static_rationale: str
    static_confidence: float
    llm_status: str
    confirmed: bool | None
    severity: str | None
    cvss_score: float | None
    confidence: float | None
    explanation: str | None
    attack_scenario: str | None
    recommendation: str | None
    cwe: str | None
    unified_diff: str | None
    patch_valid: bool | None
    patch_error: str | None
