import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PortfolioControlProfile(Base):
    __tablename__ = "portfolio_control_profiles"
    __table_args__ = (UniqueConstraint("portfolio_id", "version", name="uq_portfolio_control_profile_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    portfolio_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_portfolios.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(24), nullable=False)
    profile_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    document: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PortfolioSnapshot(Base):
    __tablename__ = "portfolio_snapshots"
    __table_args__ = (
        UniqueConstraint("portfolio_id", "sequence", name="uq_portfolio_snapshot_sequence"),
        UniqueConstraint("portfolio_id", "idempotency_key", name="uq_portfolio_snapshot_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    portfolio_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_portfolios.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(24), nullable=False)
    actor: Mapped[str] = mapped_column(String(180), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(180), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    previous_snapshot_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("portfolio_snapshots.id", ondelete="SET NULL"), nullable=True
    )
    previous_snapshot_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dashboard_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    governance_profile_id: Mapped[str] = mapped_column(String(36), nullable=False)
    governance_version: Mapped[int] = mapped_column(Integer, nullable=False)
    governance_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    control_profile_id: Mapped[str] = mapped_column(String(36), nullable=False)
    control_profile_version: Mapped[int] = mapped_column(Integer, nullable=False)
    control_profile_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    dashboard: Mapped[dict] = mapped_column(JSON, nullable=False)
    transition: Mapped[dict] = mapped_column(JSON, nullable=False)


class PortfolioAlert(Base):
    __tablename__ = "portfolio_alerts"
    __table_args__ = (UniqueConstraint("portfolio_id", "condition_key", name="uq_portfolio_alert_condition"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    portfolio_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_portfolios.id", ondelete="CASCADE"), nullable=False, index=True
    )
    condition_key: Mapped[str] = mapped_column(String(300), nullable=False)
    rule_key: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    first_snapshot_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("portfolio_snapshots.id", ondelete="SET NULL"), nullable=True
    )
    last_seen_snapshot_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("portfolio_snapshots.id", ondelete="SET NULL"), nullable=True
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(240), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    route_labels: Mapped[list] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="open", index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(180), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class PortfolioAuditEvent(Base):
    __tablename__ = "portfolio_audit_events"
    __table_args__ = (UniqueConstraint("portfolio_id", "sequence", name="uq_portfolio_audit_sequence"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    portfolio_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_portfolios.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(180), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    snapshot_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("portfolio_snapshots.id", ondelete="SET NULL"), nullable=True
    )
    alert_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("portfolio_alerts.id", ondelete="SET NULL"), nullable=True
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    previous_event_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
