import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(Text)
    line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    language: Mapped[str] = mapped_column(String(32))
    snippet: Mapped[str] = mapped_column(Text)
    static_rationale: Mapped[str] = mapped_column(Text)
    static_confidence: Mapped[float] = mapped_column(Float)

    llm_status: Mapped[str] = mapped_column(String(32), default="pending")
    confirmed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_scenario: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    unified_diff: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    patch_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    patch_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="findings")
    decision = relationship(
        "ReviewDecision", back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
