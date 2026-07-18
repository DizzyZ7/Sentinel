from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanProgress(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    stage: str
    status: str
    current: int = Field(ge=0)
    total: int = Field(ge=1)
    percent: int = Field(ge=0, le=100)
    message: str
    created_at: datetime


class ScanEventResponse(ScanProgress):
    id: str
    scan_id: str
