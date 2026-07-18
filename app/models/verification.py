from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class RegressionVerification(Base):
    __tablename__ = "regression_verifications"

    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    status: Mapped[str] = mapped_column(String(24), index=True)
    mode: Mapped[str] = mapped_column(String(32), default="non_executing_static_regression")
    verifier_version: Mapped[str] = mapped_column(String(16), default="0.4.0")
    before_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    after_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    patch_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    source_executed: Mapped[bool] = mapped_column(Boolean, default=False)
    before_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    after_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    checks: Mapped[list[dict]] = mapped_column(JSON, default=list)
    artifact_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    finding = relationship("Finding", back_populates="verification")
