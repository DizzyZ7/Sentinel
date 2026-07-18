from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class SecurityPolicyProfile(Base):
    __tablename__ = "security_policy_profiles"
    __table_args__ = (UniqueConstraint("root_scan_id", "version", name="uq_security_policy_root_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    root_scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(24), nullable=False)
    policy_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    document: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScanPolicyAssignment(Base):
    __tablename__ = "scan_policy_assignments"

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_policy_profiles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
