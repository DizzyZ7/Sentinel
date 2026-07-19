from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.version import APP_VERSION
from app.models.control_plane import (
    PortfolioAlert,
    PortfolioAuditEvent,
    PortfolioControlProfile,
    PortfolioSnapshot,
)
from app.models.portfolio import PortfolioGovernanceProfile, SecurityPortfolio
from app.schemas.control_plane import (
    AlertAcknowledgeRequest,
    AlertResolveRequest,
    ControlPlaneChainVerification,
    ControlPlaneIntegrity,
    PortfolioAlertResponse,
    PortfolioAuditEventResponse,
    PortfolioControlDocument,
    PortfolioControlPlaneEvidence,
    PortfolioControlPlaneSchedule,
    PortfolioControlPlaneTimeline,
    PortfolioControlProfileResponse,
    PortfolioControlStatus,
    PortfolioMemberTransition,
    PortfolioSnapshotCaptureResult,
    PortfolioSnapshotDetail,
    PortfolioSnapshotSummary,
    PortfolioSnapshotTransition,
    SnapshotCaptureRequest,
)
from app.schemas.portfolio import PortfolioDashboard
from app.services.portfolio import (
    PORTFOLIO_ENGINE_VERSION,
    build_portfolio_dashboard,
    portfolio_response,
)

CONTROL_PLANE_ENGINE_VERSION = "sentinel-control-plane-v1"
ALERT_ENGINE_VERSION = "sentinel-portfolio-alerts-v1"
AUDIT_CHAIN_VERSION = "sentinel-portfolio-audit-chain-v1"
STATE_RANK = {"passed": 0, "at_risk": 1, "blocked": 2, "insufficient_evidence": 3}
SUMMARY_DELTA_KEYS = (
    "blocked_members",
    "at_risk_members",
    "confirmed_findings",
    "policy_blockers",
    "accepted_risk_findings",
    "sla_at_risk",
    "sla_overdue",
    "missed_objectives",
    "at_risk_objectives",
    "off_track_forecasts",
    "insufficient_forecasts",
    "weighted_posture_score",
    "weighted_residual_risk",
    "top_risk_concentration_percent",
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def default_control_document() -> PortfolioControlDocument:
    return PortfolioControlDocument()


def control_profile_sha256(document: PortfolioControlDocument) -> str:
    return _sha256(document.model_dump(mode="json"))


def _audit_hash_body(
    *,
    portfolio_id: str,
    sequence: int,
    event_type: str,
    actor: str,
    occurred_at: datetime,
    snapshot_id: str | None,
    alert_id: str | None,
    payload: dict,
    previous_event_sha256: str | None,
) -> dict:
    return {
        "portfolio_id": portfolio_id,
        "sequence": sequence,
        "event_type": event_type,
        "actor": actor,
        "occurred_at": _utc(occurred_at).isoformat(),
        "snapshot_id": snapshot_id,
        "alert_id": alert_id,
        "payload": payload,
        "previous_event_sha256": previous_event_sha256,
    }


def _snapshot_hash_body(
    *,
    portfolio_id: str,
    sequence: int,
    source: str,
    actor: str,
    idempotency_key: str | None,
    captured_at: datetime,
    previous_snapshot_id: str | None,
    previous_snapshot_sha256: str | None,
    dashboard_sha256: str,
    state: str,
    governance_profile_id: str,
    governance_version: int,
    governance_sha256: str,
    control_profile_id: str,
    control_profile_version: int,
    control_profile_sha256: str,
    transition: dict,
) -> dict:
    return {
        "portfolio_id": portfolio_id,
        "sequence": sequence,
        "source": source,
        "actor": actor,
        "idempotency_key": idempotency_key,
        "captured_at": _utc(captured_at).isoformat(),
        "previous_snapshot_id": previous_snapshot_id,
        "previous_snapshot_sha256": previous_snapshot_sha256,
        "dashboard_sha256": dashboard_sha256,
        "state": state,
        "governance_profile_id": governance_profile_id,
        "governance_version": governance_version,
        "governance_sha256": governance_sha256,
        "control_profile_id": control_profile_id,
        "control_profile_version": control_profile_version,
        "control_profile_sha256": control_profile_sha256,
        "transition": transition,
    }


async def _profiles(db: AsyncSession, portfolio_id: str) -> list[PortfolioControlProfile]:
    result = await db.execute(
        select(PortfolioControlProfile)
        .where(PortfolioControlProfile.portfolio_id == portfolio_id)
        .order_by(PortfolioControlProfile.version)
    )
    return list(result.scalars())


def _profile_response(
    profile: PortfolioControlProfile,
    latest_version: int,
) -> PortfolioControlProfileResponse:
    return PortfolioControlProfileResponse(
        profile_id=profile.id,
        portfolio_id=profile.portfolio_id,
        version=profile.version,
        source=profile.source,
        profile_sha256=profile.profile_sha256,
        document=PortfolioControlDocument.model_validate(profile.document),
        created_at=profile.created_at,
        latest=profile.version == latest_version,
    )


async def append_audit_event(
    db: AsyncSession,
    portfolio_id: str,
    event_type: str,
    *,
    actor: str,
    payload: dict,
    occurred_at: datetime | None = None,
    snapshot_id: str | None = None,
    alert_id: str | None = None,
) -> PortfolioAuditEvent:
    moment = _utc(occurred_at or datetime.now(UTC))
    result = await db.execute(
        select(PortfolioAuditEvent)
        .where(PortfolioAuditEvent.portfolio_id == portfolio_id)
        .order_by(PortfolioAuditEvent.sequence.desc())
        .limit(1)
    )
    previous = result.scalar_one_or_none()
    sequence = (previous.sequence if previous else 0) + 1
    previous_hash = previous.event_sha256 if previous else None
    body = _audit_hash_body(
        portfolio_id=portfolio_id,
        sequence=sequence,
        event_type=event_type,
        actor=actor,
        occurred_at=moment,
        snapshot_id=snapshot_id,
        alert_id=alert_id,
        payload=payload,
        previous_event_sha256=previous_hash,
    )
    event = PortfolioAuditEvent(
        portfolio_id=portfolio_id,
        sequence=sequence,
        event_type=event_type,
        actor=actor,
        occurred_at=moment,
        snapshot_id=snapshot_id,
        alert_id=alert_id,
        payload=payload,
        previous_event_sha256=previous_hash,
        event_sha256=_sha256(body),
    )
    db.add(event)
    await db.flush()
    return event


async def ensure_control_profile(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    *,
    actor: str = "sentinel",
    occurred_at: datetime | None = None,
) -> PortfolioControlProfile:
    profiles = await _profiles(db, portfolio.id)
    if profiles:
        return profiles[-1]
    document = default_control_document()
    profile = PortfolioControlProfile(
        portfolio_id=portfolio.id,
        version=1,
        source="built_in",
        profile_sha256=control_profile_sha256(document),
        document=document.model_dump(mode="json"),
    )
    db.add(profile)
    await db.flush()
    await append_audit_event(
        db,
        portfolio.id,
        "control_profile_created",
        actor=actor,
        occurred_at=occurred_at,
        payload={
            "profile_id": profile.id,
            "version": profile.version,
            "profile_sha256": profile.profile_sha256,
            "source": profile.source,
        },
    )
    return profile


async def control_status(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    *,
    actor: str = "sentinel",
    occurred_at: datetime | None = None,
) -> PortfolioControlStatus:
    await ensure_control_profile(db, portfolio, actor=actor, occurred_at=occurred_at)
    profiles = await _profiles(db, portfolio.id)
    latest = profiles[-1]
    return PortfolioControlStatus(
        portfolio_id=portfolio.id,
        latest_profile=_profile_response(latest, latest.version),
        versions=[_profile_response(item, latest.version) for item in profiles],
    )


async def create_control_profile_version(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    document: PortfolioControlDocument,
    *,
    actor: str = "local-operator",
    occurred_at: datetime | None = None,
) -> PortfolioControlProfile:
    profiles = await _profiles(db, portfolio.id)
    digest = control_profile_sha256(document)
    if profiles and profiles[-1].profile_sha256 == digest:
        return profiles[-1]
    version = (profiles[-1].version if profiles else 0) + 1
    profile = PortfolioControlProfile(
        portfolio_id=portfolio.id,
        version=version,
        source="declared",
        profile_sha256=digest,
        document=document.model_dump(mode="json"),
    )
    db.add(profile)
    await db.flush()
    await append_audit_event(
        db,
        portfolio.id,
        "control_profile_version_created",
        actor=actor,
        occurred_at=occurred_at,
        payload={
            "profile_id": profile.id,
            "version": profile.version,
            "profile_sha256": profile.profile_sha256,
            "previous_profile_sha256": profiles[-1].profile_sha256 if profiles else None,
        },
    )
    return profile


async def _snapshot_rows(db: AsyncSession, portfolio_id: str) -> list[PortfolioSnapshot]:
    result = await db.execute(
        select(PortfolioSnapshot)
        .where(PortfolioSnapshot.portfolio_id == portfolio_id)
        .order_by(PortfolioSnapshot.sequence)
    )
    return list(result.scalars())


async def _latest_snapshot(db: AsyncSession, portfolio_id: str) -> PortfolioSnapshot | None:
    result = await db.execute(
        select(PortfolioSnapshot)
        .where(PortfolioSnapshot.portfolio_id == portfolio_id)
        .order_by(PortfolioSnapshot.sequence.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


def _number(value: Any) -> float:
    if value is None:
        return 0.0
    return float(value)


def _transition(
    previous: PortfolioSnapshot | None,
    current: PortfolioDashboard,
) -> PortfolioSnapshotTransition:
    previous_dashboard = PortfolioDashboard.model_validate(previous.dashboard) if previous else None
    from_state = previous_dashboard.summary.state if previous_dashboard else None
    to_state = current.summary.state
    if previous_dashboard is None:
        direction = "initial"
    else:
        current_rank = STATE_RANK[to_state]
        previous_rank = STATE_RANK[from_state]
        if current_rank < previous_rank:
            direction = "improved"
        elif current_rank > previous_rank:
            direction = "degraded"
        else:
            direction = "unchanged"

    deltas: dict[str, float] = {}
    if previous_dashboard is not None:
        old_summary = previous_dashboard.summary.model_dump(mode="json")
        new_summary = current.summary.model_dump(mode="json")
        for key in SUMMARY_DELTA_KEYS:
            delta = round(_number(new_summary.get(key)) - _number(old_summary.get(key)), 2)
            if delta:
                deltas[key] = delta

    old_members = {item.root_scan_id: item for item in previous_dashboard.members} if previous_dashboard else {}
    new_members = {item.root_scan_id: item for item in current.members}
    member_transitions: list[PortfolioMemberTransition] = []
    for root_scan_id in sorted(set(old_members) | set(new_members)):
        old = old_members.get(root_scan_id)
        new = new_members.get(root_scan_id)
        if old is None and new is not None:
            member_transitions.append(
                PortfolioMemberTransition(
                    root_scan_id=root_scan_id,
                    display_name=new.display_name,
                    change_type="added",
                    current_readiness=new.readiness,
                    current_evidence_state=new.evidence_state,
                    changes=["Member added to portfolio scope."],
                )
            )
            continue
        if new is None and old is not None:
            member_transitions.append(
                PortfolioMemberTransition(
                    root_scan_id=root_scan_id,
                    display_name=old.display_name,
                    change_type="removed",
                    previous_readiness=old.readiness,
                    previous_evidence_state=old.evidence_state,
                    changes=["Member removed from portfolio scope."],
                )
            )
            continue
        assert old is not None and new is not None
        changes: list[str] = []
        for field, label in (
            ("readiness", "Readiness"),
            ("evidence_state", "Evidence state"),
            ("scan_id", "Selected scan"),
            ("criticality", "Criticality"),
            ("release_gate_state", "Release gate"),
            ("policy_state", "Policy state"),
            ("governance_state", "Governance state"),
            ("objective_state", "Objective state"),
            ("forecast_status", "Forecast status"),
        ):
            before = getattr(old, field)
            after = getattr(new, field)
            if before != after:
                changes.append(f"{label}: {before} -> {after}.")
        if changes:
            member_transitions.append(
                PortfolioMemberTransition(
                    root_scan_id=root_scan_id,
                    display_name=new.display_name,
                    change_type="changed",
                    previous_readiness=old.readiness,
                    current_readiness=new.readiness,
                    previous_evidence_state=old.evidence_state,
                    current_evidence_state=new.evidence_state,
                    changes=changes,
                )
            )

    old_missed = (
        {item.key for item in previous_dashboard.checks if item.status == "missed"} if previous_dashboard else set()
    )
    new_missed = {item.key for item in current.checks if item.status == "missed"}
    reasons: list[str] = []
    if direction == "initial":
        reasons.append(f"Initial control-plane snapshot captured with state {to_state}.")
    elif direction != "unchanged":
        reasons.append(f"Portfolio state changed from {from_state} to {to_state}.")
    if deltas:
        reasons.append(f"{len(deltas)} portfolio summary metric(s) changed.")
    if member_transitions:
        reasons.append(f"{len(member_transitions)} member transition(s) detected.")
    return PortfolioSnapshotTransition(
        from_snapshot_id=previous.id if previous else None,
        from_state=from_state,
        to_state=to_state,
        direction=direction,
        changed=bool(
            previous is None or from_state != to_state or deltas or member_transitions or old_missed != new_missed
        ),
        summary_deltas=deltas,
        member_transitions=member_transitions,
        newly_missed_checks=sorted(new_missed - old_missed),
        cleared_checks=sorted(old_missed - new_missed),
        reasons=reasons,
    )


def _snapshot_summary(row: PortfolioSnapshot) -> PortfolioSnapshotSummary:
    return PortfolioSnapshotSummary(
        snapshot_id=row.id,
        portfolio_id=row.portfolio_id,
        sequence=row.sequence,
        source=row.source,
        actor=row.actor,
        idempotency_key=row.idempotency_key,
        captured_at=row.captured_at,
        state=row.state,
        previous_snapshot_id=row.previous_snapshot_id,
        previous_snapshot_sha256=row.previous_snapshot_sha256,
        dashboard_sha256=row.dashboard_sha256,
        snapshot_sha256=row.snapshot_sha256,
        governance_profile_id=row.governance_profile_id,
        governance_version=row.governance_version,
        governance_sha256=row.governance_sha256,
        control_profile_id=row.control_profile_id,
        control_profile_version=row.control_profile_version,
        control_profile_sha256=row.control_profile_sha256,
        transition=PortfolioSnapshotTransition.model_validate(row.transition),
    )


def snapshot_detail(row: PortfolioSnapshot) -> PortfolioSnapshotDetail:
    return PortfolioSnapshotDetail(
        **_snapshot_summary(row).model_dump(),
        dashboard=PortfolioDashboard.model_validate(row.dashboard),
    )


def alert_response(row: PortfolioAlert) -> PortfolioAlertResponse:
    return PortfolioAlertResponse(
        alert_id=row.id,
        portfolio_id=row.portfolio_id,
        condition_key=row.condition_key,
        rule_key=row.rule_key,
        first_snapshot_id=row.first_snapshot_id,
        last_seen_snapshot_id=row.last_seen_snapshot_id,
        severity=row.severity,
        title=row.title,
        detail=row.detail,
        route_labels=list(row.route_labels or []),
        status=row.status,
        occurrence_count=row.occurrence_count,
        created_at=row.created_at,
        updated_at=row.updated_at,
        acknowledged_at=row.acknowledged_at,
        acknowledged_by=row.acknowledged_by,
        resolved_at=row.resolved_at,
        resolution_reason=row.resolution_reason,
    )


def _audit_response(row: PortfolioAuditEvent) -> PortfolioAuditEventResponse:
    return PortfolioAuditEventResponse(
        event_id=row.id,
        portfolio_id=row.portfolio_id,
        sequence=row.sequence,
        event_type=row.event_type,
        actor=row.actor,
        occurred_at=row.occurred_at,
        snapshot_id=row.snapshot_id,
        alert_id=row.alert_id,
        payload=row.payload,
        previous_event_sha256=row.previous_event_sha256,
        event_sha256=row.event_sha256,
    )


@dataclass(frozen=True, slots=True)
class AlertSpec:
    condition_key: str
    rule_key: str
    severity: str
    title: str
    detail: str
    persistent: bool = True


def _alert_specs(
    dashboard: PortfolioDashboard,
    transition: PortfolioSnapshotTransition,
    document: PortfolioControlDocument,
    snapshot_id: str,
) -> list[AlertSpec]:
    specs: list[AlertSpec] = []
    state = dashboard.summary.state
    if state == "at_risk" and document.alert_on_at_risk:
        specs.append(
            AlertSpec(
                "portfolio:at_risk",
                "portfolio_at_risk",
                "warning",
                "Portfolio is at risk",
                "Portfolio governance passes, but one or more member lineages remain at risk.",
            )
        )
    if state == "blocked" and document.alert_on_blocked:
        specs.append(
            AlertSpec(
                "portfolio:blocked",
                "portfolio_blocked",
                "critical",
                "Portfolio is blocked",
                "One or more portfolio governance checks are missed.",
            )
        )
    if state == "insufficient_evidence" and document.alert_on_insufficient_evidence:
        specs.append(
            AlertSpec(
                "portfolio:insufficient_evidence",
                "portfolio_insufficient_evidence",
                "critical",
                "Portfolio evidence is insufficient",
                "Required portfolio evidence is missing, stale, unavailable, ambiguous, or the portfolio is empty.",
            )
        )
    if document.alert_on_member_blocked:
        for member in dashboard.members:
            if member.readiness == "blocked":
                severity = "critical" if member.criticality in {"critical", "high"} else "high"
                specs.append(
                    AlertSpec(
                        f"member:{member.root_scan_id}:blocked",
                        "member_blocked",
                        severity,
                        f"{member.display_name} is blocked",
                        "; ".join(member.reasons) or "Member readiness is blocked.",
                    )
                )
    if document.alert_on_evidence_degradation:
        for member in dashboard.members:
            if member.evidence_state != "current":
                specs.append(
                    AlertSpec(
                        f"member:{member.root_scan_id}:evidence:{member.evidence_state}",
                        "evidence_degradation",
                        "high",
                        f"{member.display_name} evidence is {member.evidence_state}",
                        f"Selected evidence state is {member.evidence_state}; branch heads: {member.branch_heads}.",
                    )
                )
    if dashboard.summary.sla_overdue > 0 and document.alert_on_sla_overdue:
        specs.append(
            AlertSpec(
                "portfolio:sla_overdue",
                "sla_overdue",
                "critical",
                "Portfolio has overdue SLA debt",
                f"{dashboard.summary.sla_overdue} finding(s) are overdue.",
            )
        )
    if dashboard.summary.missed_objectives > 0 and document.alert_on_objective_missed:
        specs.append(
            AlertSpec(
                "portfolio:objective_missed",
                "objective_missed",
                "critical",
                "Security objectives are missed",
                f"{dashboard.summary.missed_objectives} lineage objective(s) are missed.",
            )
        )
    if dashboard.summary.off_track_forecasts > 0 and document.alert_on_forecast_off_track:
        specs.append(
            AlertSpec(
                "portfolio:forecast_off_track",
                "forecast_off_track",
                "high",
                "Remediation capacity is off track",
                f"{dashboard.summary.off_track_forecasts} lineage forecast(s) are off track or missed.",
            )
        )
    if document.alert_on_governance_miss:
        for check in dashboard.checks:
            if check.status == "missed":
                specs.append(
                    AlertSpec(
                        f"governance:{check.key}",
                        "governance_check_missed",
                        "high",
                        f"Governance check missed: {check.label}",
                        check.explanation,
                    )
                )
    if transition.direction == "degraded" and document.alert_on_state_regression:
        specs.append(
            AlertSpec(
                f"event:state_regression:{snapshot_id}",
                "state_regression",
                "high",
                "Portfolio state regressed",
                f"Portfolio state changed from {transition.from_state} to {transition.to_state}.",
                persistent=False,
            )
        )
    if transition.direction == "improved" and document.alert_on_recovery:
        specs.append(
            AlertSpec(
                f"event:recovery:{snapshot_id}",
                "portfolio_recovery",
                "info",
                "Portfolio state improved",
                f"Portfolio state changed from {transition.from_state} to {transition.to_state}.",
                persistent=False,
            )
        )
    return specs


async def _alerts(db: AsyncSession, portfolio_id: str) -> list[PortfolioAlert]:
    result = await db.execute(
        select(PortfolioAlert)
        .where(PortfolioAlert.portfolio_id == portfolio_id)
        .order_by(PortfolioAlert.created_at.desc(), PortfolioAlert.id)
    )
    return list(result.scalars())


async def _evaluate_alerts(
    db: AsyncSession,
    snapshot: PortfolioSnapshot,
    dashboard: PortfolioDashboard,
    transition: PortfolioSnapshotTransition,
    document: PortfolioControlDocument,
    *,
    actor: str,
    occurred_at: datetime,
) -> tuple[int, int, int]:
    specs = _alert_specs(dashboard, transition, document, snapshot.id)
    existing = {item.condition_key: item for item in await _alerts(db, snapshot.portfolio_id)}
    persistent_active = {item.condition_key for item in specs if item.persistent}
    opened = reopened = resolved = 0
    for spec in specs:
        alert = existing.get(spec.condition_key)
        if alert is None:
            alert = PortfolioAlert(
                portfolio_id=snapshot.portfolio_id,
                condition_key=spec.condition_key,
                rule_key=spec.rule_key,
                first_snapshot_id=snapshot.id,
                last_seen_snapshot_id=snapshot.id,
                severity=spec.severity,
                title=spec.title,
                detail=spec.detail,
                route_labels=document.route_labels,
                status="open",
                occurrence_count=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
            db.add(alert)
            await db.flush()
            opened += 1
            await append_audit_event(
                db,
                snapshot.portfolio_id,
                "alert_opened",
                actor=actor,
                occurred_at=occurred_at,
                snapshot_id=snapshot.id,
                alert_id=alert.id,
                payload={
                    "condition_key": spec.condition_key,
                    "rule_key": spec.rule_key,
                    "severity": spec.severity,
                    "routes": document.route_labels,
                },
            )
            continue
        if alert.last_seen_snapshot_id != snapshot.id:
            alert.occurrence_count += 1
        alert.last_seen_snapshot_id = snapshot.id
        alert.severity = spec.severity
        alert.title = spec.title
        alert.detail = spec.detail
        alert.route_labels = document.route_labels
        alert.updated_at = occurred_at
        if alert.status == "resolved":
            alert.status = "open"
            alert.acknowledged_at = None
            alert.acknowledged_by = None
            alert.resolved_at = None
            alert.resolution_reason = None
            reopened += 1
            await append_audit_event(
                db,
                snapshot.portfolio_id,
                "alert_reopened",
                actor=actor,
                occurred_at=occurred_at,
                snapshot_id=snapshot.id,
                alert_id=alert.id,
                payload={"condition_key": spec.condition_key, "occurrence_count": alert.occurrence_count},
            )
    if document.auto_resolve_cleared_alerts:
        for alert in existing.values():
            if alert.condition_key.startswith("event:"):
                continue
            if alert.status == "resolved" or alert.condition_key in persistent_active:
                continue
            alert.status = "resolved"
            alert.resolved_at = occurred_at
            alert.resolution_reason = f"Condition cleared by snapshot {snapshot.id}."
            alert.updated_at = occurred_at
            resolved += 1
            await append_audit_event(
                db,
                snapshot.portfolio_id,
                "alert_auto_resolved",
                actor="sentinel",
                occurred_at=occurred_at,
                snapshot_id=snapshot.id,
                alert_id=alert.id,
                payload={"condition_key": alert.condition_key, "reason": alert.resolution_reason},
            )
    await db.flush()
    return opened, reopened, resolved


async def capture_snapshot(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    request: SnapshotCaptureRequest,
    *,
    captured_at: datetime | None = None,
) -> PortfolioSnapshotCaptureResult:
    moment = _utc(captured_at or datetime.now(UTC))
    if request.idempotency_key:
        result = await db.execute(
            select(PortfolioSnapshot).where(
                PortfolioSnapshot.portfolio_id == portfolio.id,
                PortfolioSnapshot.idempotency_key == request.idempotency_key,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return PortfolioSnapshotCaptureResult(created=False, snapshot=snapshot_detail(existing))
    profile = await ensure_control_profile(db, portfolio, actor=request.actor, occurred_at=moment)
    document = PortfolioControlDocument.model_validate(profile.document)
    previous = await _latest_snapshot(db, portfolio.id)
    dashboard = await build_portfolio_dashboard(db, portfolio, generated_at=moment)
    transition = _transition(previous, dashboard)
    dashboard_payload = dashboard.model_dump(mode="json")
    dashboard_digest = _sha256(dashboard_payload)
    sequence = (previous.sequence if previous else 0) + 1
    snapshot_body = _snapshot_hash_body(
        portfolio_id=portfolio.id,
        sequence=sequence,
        source=request.source,
        actor=request.actor,
        idempotency_key=request.idempotency_key,
        captured_at=moment,
        previous_snapshot_id=previous.id if previous else None,
        previous_snapshot_sha256=previous.snapshot_sha256 if previous else None,
        dashboard_sha256=dashboard_digest,
        state=dashboard.summary.state,
        governance_profile_id=dashboard.governance.profile_id,
        governance_version=dashboard.governance.version,
        governance_sha256=dashboard.governance.governance_sha256,
        control_profile_id=profile.id,
        control_profile_version=profile.version,
        control_profile_sha256=profile.profile_sha256,
        transition=transition.model_dump(mode="json"),
    )
    snapshot = PortfolioSnapshot(
        portfolio_id=portfolio.id,
        sequence=sequence,
        source=request.source,
        actor=request.actor,
        idempotency_key=request.idempotency_key,
        captured_at=moment,
        previous_snapshot_id=previous.id if previous else None,
        previous_snapshot_sha256=previous.snapshot_sha256 if previous else None,
        dashboard_sha256=dashboard_digest,
        snapshot_sha256=_sha256(snapshot_body),
        state=dashboard.summary.state,
        governance_profile_id=dashboard.governance.profile_id,
        governance_version=dashboard.governance.version,
        governance_sha256=dashboard.governance.governance_sha256,
        control_profile_id=profile.id,
        control_profile_version=profile.version,
        control_profile_sha256=profile.profile_sha256,
        dashboard=dashboard_payload,
        transition=transition.model_dump(mode="json"),
    )
    db.add(snapshot)
    await db.flush()
    await append_audit_event(
        db,
        portfolio.id,
        "portfolio_snapshot_captured",
        actor=request.actor,
        occurred_at=moment,
        snapshot_id=snapshot.id,
        payload={
            "sequence": sequence,
            "source": request.source,
            "state": snapshot.state,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "dashboard_sha256": snapshot.dashboard_sha256,
            "transition_direction": transition.direction,
        },
    )
    opened, reopened, resolved = await _evaluate_alerts(
        db,
        snapshot,
        dashboard,
        transition,
        document,
        actor=request.actor,
        occurred_at=moment,
    )
    await db.flush()
    return PortfolioSnapshotCaptureResult(
        created=True,
        snapshot=snapshot_detail(snapshot),
        alerts_opened=opened,
        alerts_reopened=reopened,
        alerts_auto_resolved=resolved,
    )


async def list_snapshots(db: AsyncSession, portfolio_id: str) -> list[PortfolioSnapshotSummary]:
    rows = await _snapshot_rows(db, portfolio_id)
    return [_snapshot_summary(item) for item in reversed(rows)]


async def get_snapshot(db: AsyncSession, portfolio_id: str, snapshot_id: str) -> PortfolioSnapshot | None:
    result = await db.execute(
        select(PortfolioSnapshot).where(
            PortfolioSnapshot.portfolio_id == portfolio_id,
            PortfolioSnapshot.id == snapshot_id,
        )
    )
    return result.scalar_one_or_none()


async def list_alerts(
    db: AsyncSession,
    portfolio_id: str,
    *,
    status: str | None = None,
    route_label: str | None = None,
) -> list[PortfolioAlertResponse]:
    rows = await _alerts(db, portfolio_id)
    output = []
    for row in rows:
        if status is not None and row.status != status:
            continue
        if route_label is not None and route_label not in (row.route_labels or []):
            continue
        output.append(alert_response(row))
    return output


async def acknowledge_alert(
    db: AsyncSession,
    portfolio_id: str,
    alert_id: str,
    request: AlertAcknowledgeRequest,
    *,
    occurred_at: datetime | None = None,
) -> PortfolioAlert:
    alert = await db.get(PortfolioAlert, alert_id)
    if alert is None or alert.portfolio_id != portfolio_id:
        raise ValueError("Portfolio alert not found")
    if alert.status == "resolved":
        raise ValueError("Resolved alerts cannot be acknowledged")
    moment = _utc(occurred_at or datetime.now(UTC))
    if alert.status != "acknowledged":
        alert.status = "acknowledged"
        alert.acknowledged_at = moment
        alert.acknowledged_by = request.actor
        alert.updated_at = moment
        await append_audit_event(
            db,
            portfolio_id,
            "alert_acknowledged",
            actor=request.actor,
            occurred_at=moment,
            snapshot_id=alert.last_seen_snapshot_id,
            alert_id=alert.id,
            payload={"condition_key": alert.condition_key},
        )
    await db.flush()
    return alert


async def resolve_alert(
    db: AsyncSession,
    portfolio_id: str,
    alert_id: str,
    request: AlertResolveRequest,
    *,
    occurred_at: datetime | None = None,
) -> PortfolioAlert:
    alert = await db.get(PortfolioAlert, alert_id)
    if alert is None or alert.portfolio_id != portfolio_id:
        raise ValueError("Portfolio alert not found")
    moment = _utc(occurred_at or datetime.now(UTC))
    if alert.status != "resolved":
        alert.status = "resolved"
        alert.resolved_at = moment
        alert.resolution_reason = request.reason
        alert.updated_at = moment
        await append_audit_event(
            db,
            portfolio_id,
            "alert_resolved",
            actor=request.actor,
            occurred_at=moment,
            snapshot_id=alert.last_seen_snapshot_id,
            alert_id=alert.id,
            payload={"condition_key": alert.condition_key, "reason": request.reason},
        )
    await db.flush()
    return alert


async def list_audit_events(
    db: AsyncSession,
    portfolio_id: str,
    *,
    limit: int = 200,
) -> list[PortfolioAuditEventResponse]:
    result = await db.execute(
        select(PortfolioAuditEvent)
        .where(PortfolioAuditEvent.portfolio_id == portfolio_id)
        .order_by(PortfolioAuditEvent.sequence.desc())
        .limit(limit)
    )
    return [_audit_response(item) for item in result.scalars()]


async def verify_control_plane_chains(
    db: AsyncSession,
    portfolio_id: str,
) -> ControlPlaneChainVerification:
    failures: list[str] = []
    snapshots = await _snapshot_rows(db, portfolio_id)
    previous_snapshot: PortfolioSnapshot | None = None
    for expected_sequence, row in enumerate(snapshots, start=1):
        if row.sequence != expected_sequence:
            failures.append(f"Snapshot sequence expected {expected_sequence}, found {row.sequence}.")
        expected_previous_id = previous_snapshot.id if previous_snapshot else None
        expected_previous_hash = previous_snapshot.snapshot_sha256 if previous_snapshot else None
        if row.previous_snapshot_id != expected_previous_id:
            failures.append(f"Snapshot {row.id} previous snapshot ID does not match the chain.")
        if row.previous_snapshot_sha256 != expected_previous_hash:
            failures.append(f"Snapshot {row.id} previous snapshot SHA-256 does not match the chain.")
        dashboard_digest = _sha256(row.dashboard)
        if dashboard_digest != row.dashboard_sha256:
            failures.append(f"Snapshot {row.id} dashboard SHA-256 is invalid.")
        expected_snapshot_hash = _sha256(
            _snapshot_hash_body(
                portfolio_id=row.portfolio_id,
                sequence=row.sequence,
                source=row.source,
                actor=row.actor,
                idempotency_key=row.idempotency_key,
                captured_at=row.captured_at,
                previous_snapshot_id=row.previous_snapshot_id,
                previous_snapshot_sha256=row.previous_snapshot_sha256,
                dashboard_sha256=row.dashboard_sha256,
                state=row.state,
                governance_profile_id=row.governance_profile_id,
                governance_version=row.governance_version,
                governance_sha256=row.governance_sha256,
                control_profile_id=row.control_profile_id,
                control_profile_version=row.control_profile_version,
                control_profile_sha256=row.control_profile_sha256,
                transition=row.transition,
            )
        )
        if expected_snapshot_hash != row.snapshot_sha256:
            failures.append(f"Snapshot {row.id} snapshot SHA-256 is invalid.")
        previous_snapshot = row

    result = await db.execute(
        select(PortfolioAuditEvent)
        .where(PortfolioAuditEvent.portfolio_id == portfolio_id)
        .order_by(PortfolioAuditEvent.sequence)
    )
    events = list(result.scalars())
    previous_event: PortfolioAuditEvent | None = None
    audit_failures = 0
    for expected_sequence, row in enumerate(events, start=1):
        if row.sequence != expected_sequence:
            failures.append(f"Audit event sequence expected {expected_sequence}, found {row.sequence}.")
            audit_failures += 1
        expected_previous_hash = previous_event.event_sha256 if previous_event else None
        if row.previous_event_sha256 != expected_previous_hash:
            failures.append(f"Audit event {row.id} previous event SHA-256 does not match the chain.")
            audit_failures += 1
        expected_event_hash = _sha256(
            _audit_hash_body(
                portfolio_id=row.portfolio_id,
                sequence=row.sequence,
                event_type=row.event_type,
                actor=row.actor,
                occurred_at=row.occurred_at,
                snapshot_id=row.snapshot_id,
                alert_id=row.alert_id,
                payload=row.payload,
                previous_event_sha256=row.previous_event_sha256,
            )
        )
        if expected_event_hash != row.event_sha256:
            failures.append(f"Audit event {row.id} event SHA-256 is invalid.")
            audit_failures += 1
        previous_event = row

    snapshot_failures = sum(item.startswith("Snapshot") for item in failures)
    return ControlPlaneChainVerification(
        snapshot_chain_valid=snapshot_failures == 0,
        audit_chain_valid=audit_failures == 0,
        snapshot_count=len(snapshots),
        audit_event_count=len(events),
        failures=failures,
    )


async def build_schedule_status(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    *,
    generated_at: datetime | None = None,
    actor: str = "sentinel",
) -> PortfolioControlPlaneSchedule:
    moment = _utc(generated_at or datetime.now(UTC))
    status = await control_status(db, portfolio, actor=actor, occurred_at=moment)
    profile = status.latest_profile
    latest = await _latest_snapshot(db, portfolio.id)
    alert_rows = await _alerts(db, portfolio.id)
    counts = {name: sum(item.status == name for item in alert_rows) for name in ("open", "acknowledged", "resolved")}
    reasons: list[str] = [
        "Snapshot execution is caller-driven through the API; Sentinel does not claim a hidden scheduler."
    ]
    configuration_changed = latest is None
    next_due_at = None
    age_hours = None
    if latest is None:
        schedule_state = "never_captured"
        reasons.append("No immutable portfolio snapshot has been captured.")
    else:
        captured = _utc(latest.captured_at)
        age_hours = max(0.0, (moment - captured).total_seconds() / 3600)
        interval = profile.document.snapshot_interval_hours
        next_due_at = captured + timedelta(hours=interval)
        if moment < next_due_at:
            schedule_state = "current"
        elif moment < next_due_at + timedelta(hours=interval):
            schedule_state = "due"
            reasons.append("The next control-plane snapshot is due.")
        else:
            schedule_state = "overdue"
            reasons.append("The control-plane snapshot is more than one cadence interval overdue.")
        latest_governance_result = await db.execute(
            select(PortfolioGovernanceProfile)
            .where(PortfolioGovernanceProfile.portfolio_id == portfolio.id)
            .order_by(PortfolioGovernanceProfile.version.desc())
            .limit(1)
        )
        latest_governance = latest_governance_result.scalar_one_or_none()
        snapshot_dashboard = PortfolioDashboard.model_validate(latest.dashboard)
        current_portfolio = await portfolio_response(db, portfolio)
        current_scope = {
            "name": current_portfolio.name,
            "description": current_portfolio.description,
            "members": [
                {
                    "root_scan_id": item.root_scan_id,
                    "pinned_scan_id": item.pinned_scan_id,
                    "display_name": item.display_name,
                    "business_unit": item.business_unit,
                    "criticality": item.criticality,
                }
                for item in current_portfolio.members
            ],
        }
        snapshot_scope = {
            "name": snapshot_dashboard.portfolio.name,
            "description": snapshot_dashboard.portfolio.description,
            "members": [
                {
                    "root_scan_id": item.root_scan_id,
                    "pinned_scan_id": item.pinned_scan_id,
                    "display_name": item.display_name,
                    "business_unit": item.business_unit,
                    "criticality": item.criticality,
                }
                for item in snapshot_dashboard.portfolio.members
            ],
        }
        configuration_changed = (
            _sha256(current_scope) != _sha256(snapshot_scope)
            or profile.profile_sha256 != latest.control_profile_sha256
            or latest_governance is None
            or latest_governance.governance_sha256 != latest.governance_sha256
        )
        if configuration_changed:
            reasons.append(
                "Portfolio membership, governance, metadata, or control policy changed after the latest snapshot."
            )
    return PortfolioControlPlaneSchedule(
        portfolio_id=portfolio.id,
        schedule_state=schedule_state,
        snapshot_interval_hours=profile.document.snapshot_interval_hours,
        latest_snapshot_id=latest.id if latest else None,
        latest_snapshot_state=latest.state if latest else None,
        latest_snapshot_at=latest.captured_at if latest else None,
        next_due_at=next_due_at,
        age_hours=round(age_hours, 2) if age_hours is not None else None,
        configuration_changed_since_snapshot=configuration_changed,
        open_alerts=counts["open"],
        acknowledged_alerts=counts["acknowledged"],
        resolved_alerts=counts["resolved"],
        reasons=reasons,
    )


async def build_timeline(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    *,
    generated_at: datetime | None = None,
    snapshot_limit: int = 50,
    event_limit: int = 200,
) -> PortfolioControlPlaneTimeline:
    moment = _utc(generated_at or datetime.now(UTC))
    control = await control_status(db, portfolio, occurred_at=moment)
    schedule = await build_schedule_status(db, portfolio, generated_at=moment)
    snapshots = (await list_snapshots(db, portfolio.id))[:snapshot_limit]
    alerts = await list_alerts(db, portfolio.id)
    events = await list_audit_events(db, portfolio.id, limit=event_limit)
    chain = await verify_control_plane_chains(db, portfolio.id)
    return PortfolioControlPlaneTimeline(
        generated_at=moment,
        portfolio_id=portfolio.id,
        control=control,
        schedule=schedule,
        chain=chain,
        snapshots=snapshots,
        alerts=alerts,
        audit_events=events,
    )


async def build_control_plane_evidence(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    *,
    generated_at: datetime | None = None,
) -> PortfolioControlPlaneEvidence:
    moment = _utc(generated_at or datetime.now(UTC))
    timeline = await build_timeline(db, portfolio, generated_at=moment, snapshot_limit=100000, event_limit=100000)
    rows = await _snapshot_rows(db, portfolio.id)
    snapshots = [snapshot_detail(item) for item in rows]
    sections: dict[str, Any] = {
        "versions": {
            "app": APP_VERSION,
            "portfolio_engine": PORTFOLIO_ENGINE_VERSION,
            "control_plane_engine": CONTROL_PLANE_ENGINE_VERSION,
            "alert_engine": ALERT_ENGINE_VERSION,
            "audit_chain": AUDIT_CHAIN_VERSION,
        },
        "portfolio_id": portfolio.id,
        "control": timeline.control.model_dump(mode="json"),
        "schedule": timeline.schedule.model_dump(mode="json"),
        "chain": timeline.chain.model_dump(mode="json"),
        "snapshots": [item.model_dump(mode="json") for item in snapshots],
        "alerts": [item.model_dump(mode="json") for item in timeline.alerts],
        "audit_events": [item.model_dump(mode="json") for item in reversed(timeline.audit_events)],
    }
    integrity = ControlPlaneIntegrity(
        section_sha256={key: _sha256(value) for key, value in sections.items()},
        payload_sha256=_sha256(sections),
    )
    return PortfolioControlPlaneEvidence(
        generated_at=moment,
        **sections,
        integrity=integrity,
    )
