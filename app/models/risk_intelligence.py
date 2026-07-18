import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class RiskIntelligence(Base):
    __tablename__ = "risk_intelligence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True, index=True
    )
    engine_version: Mapped[str] = mapped_column(String(80))
    asset_name: Mapped[str] = mapped_column(String(180))
    asset_type: Mapped[str] = mapped_column(String(64))
    component: Mapped[str] = mapped_column(String(255))
    attack_surface: Mapped[str] = mapped_column(String(64))
    exposure: Mapped[str] = mapped_column(String(32))
    data_exposure: Mapped[str] = mapped_column(String(120))
    privilege_required: Mapped[str] = mapped_column(String(32))
    blast_radius: Mapped[str] = mapped_column(String(32))
    technical_score: Mapped[float] = mapped_column(Float)
    exploitability_score: Mapped[float] = mapped_column(Float)
    exposure_score: Mapped[float] = mapped_column(Float)
    asset_importance_score: Mapped[float] = mapped_column(Float)
    confidence_score: Mapped[float] = mapped_column(Float)
    inherent_risk_score: Mapped[float] = mapped_column(Float)
    residual_risk_score: Mapped[float] = mapped_column(Float)
    priority: Mapped[str] = mapped_column(String(24), index=True)
    impact_summary: Mapped[str] = mapped_column(Text)
    business_impact: Mapped[str] = mapped_column(Text)
    recommended_action: Mapped[str] = mapped_column(Text)
    remediation_plan: Mapped[list[str]] = mapped_column(JSON, default=list)
    estimated_effort: Mapped[str] = mapped_column(String(40))
    scoring_factors: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    finding = relationship("Finding", back_populates="risk_intelligence")


    @property
    def context_profile_version(self) -> int | None:
        return (self.scoring_factors or {}).get("context", {}).get("profile_version")

    @property
    def context_sha256(self) -> str | None:
        return (self.scoring_factors or {}).get("context", {}).get("context_sha256")

    @property
    def context_source(self) -> str:
        return (self.scoring_factors or {}).get("context", {}).get("resolution_source", "heuristic")

    @property
    def context_asset_id(self) -> str | None:
        return (self.scoring_factors or {}).get("context", {}).get("asset_id")

    @property
    def context_project_name(self) -> str | None:
        return (self.scoring_factors or {}).get("context", {}).get("project_name")
