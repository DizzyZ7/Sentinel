from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DecisionRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    note: str | None = Field(default=None, max_length=1000)


class DecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    decision: Literal["approved", "rejected"]
    note: str | None
    decided_at: datetime
