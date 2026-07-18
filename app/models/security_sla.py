from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class SecuritySLAProfile(Base):
    __tablename__ = "security_sla_profiles"
    __table_args__ = (UniqueConstraint("root_scan_id", "version", name="uq_security_sla_root_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    root_scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(24), nullable=False)
    sla_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    document: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanSLAAssignment(Base):
    __tablename__ = "scan_sla_assignments"

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_sla_profiles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FindingSLA(Base):
    __tablename__ = "finding_slas"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    root_scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_sla_profiles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    origin_sla_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    effective_severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    assigned_team: Mapped[str] = mapped_column(String(180), nullable=False, index=True)
    risk_owner: Mapped[str] = mapped_column(String(180), nullable=False)
    escalation_contact: Mapped[str | None] = mapped_column(String(180), nullable=True)
    assignment_source: Mapped[str] = mapped_column(String(24), nullable=False)
    matched_override_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    at_risk_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
