from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LLMReviewOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmed: bool
    severity: Literal["low", "medium", "high", "critical"]
    cvss_score: float = Field(ge=0, le=10)
    confidence: float = Field(ge=0, le=1)
    title: str = Field(min_length=3, max_length=180)
    explanation: str = Field(min_length=10, max_length=1200)
    attack_scenario: str = Field(min_length=5, max_length=1200)
    recommendation: str = Field(min_length=5, max_length=1200)
    cwe: str = Field(pattern=r"^CWE-[0-9]+$")
    unified_diff: str
