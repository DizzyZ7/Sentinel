import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class SecurityPortfolio(Base):
    __tablename__ = "security_portfolios"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class PortfolioMember(Base):
    __tablename__ = "portfolio_members"
    __table_args__ = (UniqueConstraint("portfolio_id", "root_scan_id", name="uq_portfolio_root_member"),)

    portfolio_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_portfolios.id", ondelete="CASCADE"), primary_key=True
    )
    root_scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    pinned_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    display_name: Mapped[str] = mapped_column(String(180), nullable=False)
    business_unit: Mapped[str | None] = mapped_column(String(180), nullable=True)
    criticality: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PortfolioGovernanceProfile(Base):
    __tablename__ = "portfolio_governance_profiles"
    __table_args__ = (
        UniqueConstraint("portfolio_id", "version", name="uq_portfolio_governance_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    portfolio_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_portfolios.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(24), nullable=False)
    governance_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    document: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
