from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.risk_intelligence import ExecutiveReport

Environment = Literal["unknown", "development", "staging", "production"]
Criticality = Literal["low", "medium", "high", "critical"]
Exposure = Literal["unknown", "internal", "partner", "public"]
DataClassification = Literal["public", "internal", "confidential", "restricted"]
ProfileSource = Literal["inferred", "declared", "built_in", "preview"]
Privilege = Literal["unknown", "none", "none_or_low", "low", "authenticated", "privileged"]


class ProjectAssetContext(BaseModel):
    asset_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    name: str = Field(min_length=1, max_length=180)
    asset_type: str = Field(default="application_component", min_length=1, max_length=64)
    path_patterns: list[str] = Field(min_length=1, max_length=20)
    criticality: Criticality = "medium"
    exposure: Exposure = "unknown"
    data_classification: DataClassification = "internal"
    data_types: list[str] = Field(default_factory=list, max_length=20)
    privilege_required: Privilege | None = None
    business_impact: str | None = Field(default=None, max_length=1000)
    owner: str | None = Field(default=None, max_length=120)

    @field_validator("path_patterns")
    @classmethod
    def validate_patterns(cls, patterns: list[str]) -> list[str]:
        normalized: list[str] = []
        for pattern in patterns:
            value = pattern.strip().replace("\\", "/")
            if not value or len(value) > 240 or "\x00" in value:
                raise ValueError("Path patterns must be non-empty and at most 240 characters")
            if value.startswith("/") or ".." in value.split("/"):
                raise ValueError("Path patterns must be repository-relative and cannot contain '..'")
            normalized.append(value)
        return normalized


class ProjectContextDocument(BaseModel):
    project_name: str = Field(min_length=1, max_length=180)
    environment: Environment = "unknown"
    internet_exposed: bool | None = None
    default_criticality: Criticality = "medium"
    default_exposure: Exposure = "unknown"
    default_data_classification: DataClassification = "internal"
    compliance_frameworks: list[str] = Field(default_factory=list, max_length=20)
    assets: list[ProjectAssetContext] = Field(default_factory=list, max_length=100)

    @field_validator("compliance_frameworks")
    @classmethod
    def normalize_frameworks(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip()[:80] for value in values if value.strip()))

    @model_validator(mode="after")
    def unique_asset_ids(self):
        ids = [asset.asset_id for asset in self.assets]
        if len(ids) != len(set(ids)):
            raise ValueError("Asset IDs must be unique")
        return self


class ProjectContextProfileResponse(BaseModel):
    profile_id: str
    root_scan_id: str
    version: int
    source: ProfileSource
    context_sha256: str
    document: ProjectContextDocument
    created_at: datetime | None = None
    assigned_to_current_scan: bool = False


class ProjectContextStatus(BaseModel):
    scan_id: str
    root_scan_id: str
    assigned_profile: ProjectContextProfileResponse
    latest_profile: ProjectContextProfileResponse
    versions: list[ProjectContextProfileResponse]
    next_rescan_uses_version: int


class ProjectContextPreview(BaseModel):
    scan_id: str
    source: Literal["preview"] = "preview"
    context_sha256: str
    report: ExecutiveReport
