from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.lineage import ScanLineage
from app.models.scan import Scan
from app.models.security_objective import ScanObjectiveAssignment, SecurityObjectiveProfile
from app.schemas.security_objective import (
    ForecastConfidence,
    ForecastInterval,
    ObjectiveCheck,
    RemediationForecast,
    SecurityObjectiveDocument,
    SecurityObjectiveEvaluation,
    SecurityObjectiveEvaluationSummary,
    SecurityObjectivePreview,
    SecurityObjectiveProfileResponse,
    SecurityObjectiveReport,
    SecurityObjectiveStatus,
)
from app.schemas.security_posture import SecurityPostureTrend
from app.services.security_posture import build_security_posture_trend

OBJECTIVE_ENGINE_VERSION = "sentinel-security-objective-v1"
FORECAST_ENGINE_VERSION = "sentinel-remediation-forecast-v1"
CONFIDENCE_ORDER = {"insufficient_history": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True, slots=True)
class SecurityObjectiveSnapshot:
    profile_id: str
    root_scan_id: str
    version: int
    source: str
    objective_sha256: str
    document: SecurityObjectiveDocument


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _scan_moment(scan: Scan) -> datetime:
    return _utc(scan.completed_at or scan.created_at)


def objective_sha256(document: SecurityObjectiveDocument) -> str:
    payload = json.dumps(document.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_security_objective(raw: str | None) -> SecurityObjectiveDocument | None:
    if raw is None or not raw.strip():
        return None
    try:
        return SecurityObjectiveDocument.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError(f"Invalid security objective profile: {exc}") from exc


def default_security_objective(scan: Scan) -> SecurityObjectiveDocument:
    return SecurityObjectiveDocument(target_date=_scan_moment(scan) + timedelta(days=90))


def demo_security_objective(scan: Scan) -> SecurityObjectiveDocument:
    return SecurityObjectiveDocument(
        objective_name="Sentinel production security objective",
        target_date=_scan_moment(scan) + timedelta(days=30),
        max_posture_score=35.0,
        max_confirmed_findings=0,
        max_policy_blockers=0,
        max_overdue_findings=0,
        max_accepted_risk_findings=0,
        min_sla_attainment_rate=90.0,
        max_mean_resolution_hours=72.0,
        max_recurrence_rate=5.0,
        require_release_gate_passed=True,
        require_policy_passed=True,
        require_governance_passed=True,
        minimum_forecast_confidence="low",
    )


async def _root_scan_id(db: AsyncSession, scan: Scan) -> str:
    lineage = await db.get(ScanLineage, scan.id)
    return lineage.root_scan_id if lineage else scan.id


async def _latest_profile(db: AsyncSession, root_scan_id: str) -> SecurityObjectiveProfile | None:
    result = await db.execute(
        select(SecurityObjectiveProfile)
        .where(SecurityObjectiveProfile.root_scan_id == root_scan_id)
        .order_by(SecurityObjectiveProfile.version.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _profile(db: AsyncSession, profile_id: str) -> SecurityObjectiveProfile:
    profile = await db.get(SecurityObjectiveProfile, profile_id)
    if profile is None:
        raise ValueError("Assigned security objective profile is missing")
    return profile


def snapshot_from_profile(profile: SecurityObjectiveProfile) -> SecurityObjectiveSnapshot:
    return SecurityObjectiveSnapshot(
        profile_id=profile.id,
        root_scan_id=profile.root_scan_id,
        version=profile.version,
        source=profile.source,
        objective_sha256=profile.objective_sha256,
        document=SecurityObjectiveDocument.model_validate(profile.document),
    )


async def ensure_security_objective(
    db: AsyncSession,
    scan: Scan,
    document: SecurityObjectiveDocument | None = None,
    *,
    source: str | None = None,
) -> SecurityObjectiveProfile:
    assignment = await db.get(ScanObjectiveAssignment, scan.id)
    if assignment:
        return await _profile(db, assignment.profile_id)
    root_scan_id = await _root_scan_id(db, scan)
    latest = await _latest_profile(db, root_scan_id)
    if latest is None:
        active = document or default_security_objective(scan)
        latest = SecurityObjectiveProfile(
            id=str(uuid.uuid4()),
            root_scan_id=root_scan_id,
            version=1,
            source=source or ("declared" if document is not None else "inferred"),
            objective_sha256=objective_sha256(active),
            document=active.model_dump(mode="json"),
        )
        db.add(latest)
        await db.flush()
    db.add(ScanObjectiveAssignment(scan_id=scan.id, profile_id=latest.id))
    await db.flush()
    return latest


async def assign_latest_security_objective(
    db: AsyncSession,
    baseline: Scan,
    current: Scan,
) -> SecurityObjectiveProfile:
    await ensure_security_objective(db, baseline)
    root_scan_id = await _root_scan_id(db, baseline)
    latest = await _latest_profile(db, root_scan_id)
    assert latest is not None
    if await db.get(ScanObjectiveAssignment, current.id) is None:
        db.add(ScanObjectiveAssignment(scan_id=current.id, profile_id=latest.id))
        await db.flush()
    return latest


async def load_objective_snapshot(db: AsyncSession, scan_id: str) -> SecurityObjectiveSnapshot | None:
    assignment = await db.get(ScanObjectiveAssignment, scan_id)
    if assignment is None:
        return None
    return snapshot_from_profile(await _profile(db, assignment.profile_id))


async def create_security_objective_version(
    db: AsyncSession,
    scan: Scan,
    document: SecurityObjectiveDocument,
) -> SecurityObjectiveProfile:
    root_scan_id = await _root_scan_id(db, scan)
    latest = await _latest_profile(db, root_scan_id)
    digest = objective_sha256(document)
    if latest is not None and latest.objective_sha256 == digest:
        return latest
    result = await db.execute(
        select(func.max(SecurityObjectiveProfile.version)).where(
            SecurityObjectiveProfile.root_scan_id == root_scan_id
        )
    )
    profile = SecurityObjectiveProfile(
        id=str(uuid.uuid4()),
        root_scan_id=root_scan_id,
        version=(result.scalar_one() or 0) + 1,
        source="declared",
        objective_sha256=digest,
        document=document.model_dump(mode="json"),
    )
    db.add(profile)
    await db.flush()
    return profile


def _profile_response(
    profile: SecurityObjectiveProfile,
    assigned_id: str,
) -> SecurityObjectiveProfileResponse:
    return SecurityObjectiveProfileResponse(
        profile_id=profile.id,
        root_scan_id=profile.root_scan_id,
        version=profile.version,
        source=profile.source,
        objective_sha256=profile.objective_sha256,
        document=SecurityObjectiveDocument.model_validate(profile.document),
        created_at=profile.created_at,
        assigned_to_current_scan=profile.id == assigned_id,
    )


async def build_security_objective_status(
    db: AsyncSession,
    scan: Scan,
) -> SecurityObjectiveStatus:
    assigned = await ensure_security_objective(db, scan)
    result = await db.execute(
        select(SecurityObjectiveProfile)
        .where(SecurityObjectiveProfile.root_scan_id == assigned.root_scan_id)
        .order_by(SecurityObjectiveProfile.version)
    )
    profiles = list(result.scalars())
    latest = profiles[-1]
    return SecurityObjectiveStatus(
        scan_id=scan.id,
        root_scan_id=assigned.root_scan_id,
        assigned_profile=_profile_response(assigned, assigned.id),
        latest_profile=_profile_response(latest, assigned.id),
        versions=[_profile_response(item, assigned.id) for item in profiles],
        next_rescan_uses_version=latest.version,
    )


def _numeric_check(
    *,
    key: str,
    label: str,
    operator: str,
    target: float | int,
    actual: float | int | None,
    source: str,
) -> ObjectiveCheck:
    if actual is None:
        return ObjectiveCheck(
            key=key,
            label=label,
            operator=operator,
            target=target,
            actual=None,
            status="not_measurable",
            source=source,
            explanation=f"{label} has no measurable lineage history yet.",
        )
    met = actual <= target if operator == "<=" else actual >= target
    return ObjectiveCheck(
        key=key,
        label=label,
        operator=operator,
        target=target,
        actual=actual,
        status="met" if met else "missed",
        source=source,
        explanation=f"Actual {actual} {operator} target {target}: {'met' if met else 'missed'}.",
    )


def _boolean_check(
    *,
    key: str,
    label: str,
    required: bool,
    actual: bool,
    source: str,
) -> ObjectiveCheck | None:
    if not required:
        return None
    return ObjectiveCheck(
        key=key,
        label=label,
        operator="==",
        target=True,
        actual=actual,
        status="met" if actual else "missed",
        source=source,
        explanation=f"{label} is {'satisfied' if actual else 'not satisfied'}.",
    )


def evaluate_security_objective(
    trend: SecurityPostureTrend,
    snapshot: SecurityObjectiveSnapshot,
    *,
    as_of: datetime,
) -> SecurityObjectiveEvaluation:
    moment = _utc(as_of)
    document = snapshot.document
    current = trend.points[-1]
    remediation = trend.remediation
    checks: list[ObjectiveCheck] = [
        _numeric_check(
            key="posture_score",
            label="Posture score",
            operator="<=",
            target=document.max_posture_score,
            actual=current.posture_score,
            source="security_posture.summary",
        ),
        _numeric_check(
            key="confirmed_findings",
            label="Confirmed active findings",
            operator="<=",
            target=document.max_confirmed_findings,
            actual=current.confirmed_findings,
            source="security_posture.current_generation",
        ),
        _numeric_check(
            key="policy_blockers",
            label="Policy blockers",
            operator="<=",
            target=document.max_policy_blockers,
            actual=current.policy_blockers,
            source="security_policy_compliance",
        ),
        _numeric_check(
            key="overdue_findings",
            label="Overdue SLA findings",
            operator="<=",
            target=document.max_overdue_findings,
            actual=current.sla_overdue,
            source="security_sla",
        ),
        _numeric_check(
            key="accepted_risk_findings",
            label="Accepted-risk findings",
            operator="<=",
            target=document.max_accepted_risk_findings,
            actual=current.accepted_risk_findings,
            source="risk_exception_governance",
        ),
        _numeric_check(
            key="sla_attainment_rate",
            label="SLA attainment rate",
            operator=">=",
            target=document.min_sla_attainment_rate,
            actual=remediation.sla_attainment_rate,
            source="security_posture.remediation",
        ),
        _numeric_check(
            key="mean_resolution_hours",
            label="Mean remediation time in hours",
            operator="<=",
            target=document.max_mean_resolution_hours,
            actual=remediation.mean_resolution_hours,
            source="security_posture.remediation",
        ),
        _numeric_check(
            key="recurrence_rate",
            label="Exact-fingerprint recurrence rate",
            operator="<=",
            target=document.max_recurrence_rate,
            actual=remediation.recurrence_rate,
            source="security_posture.remediation",
        ),
    ]
    for check in (
        _boolean_check(
            key="release_gate",
            label="Base release gate",
            required=document.require_release_gate_passed,
            actual=current.release_gate_state == "passed",
            source="release_gate",
        ),
        _boolean_check(
            key="security_policy",
            label="Security policy compliance",
            required=document.require_policy_passed,
            actual=current.policy_state == "passed",
            source="security_policy_compliance",
        ),
        _boolean_check(
            key="governance",
            label="Exception-aware governance",
            required=document.require_governance_passed,
            actual=current.governance_state == "passed",
            source="risk_exception_governance",
        ),
    ):
        if check is not None:
            checks.append(check)

    met_checks = sum(item.status == "met" for item in checks)
    missed_checks = sum(item.status == "missed" for item in checks)
    not_measurable = sum(item.status == "not_measurable" for item in checks)
    target = _utc(document.target_date)
    remaining_seconds = (target - moment).total_seconds()
    if remaining_seconds > 86400:
        deadline_state = "future"
    elif remaining_seconds >= 0:
        deadline_state = "due"
    else:
        deadline_state = "past"
    if missed_checks:
        state = "missed" if deadline_state == "past" else "at_risk"
    elif not_measurable and document.require_measurable_history:
        state = "insufficient_history"
    else:
        state = "met"
    return SecurityObjectiveEvaluation(
        state=state,
        met=state == "met",
        as_of=moment,
        target_date=target,
        deadline_state=deadline_state,
        days_remaining=round(remaining_seconds / 86400, 2),
        summary=SecurityObjectiveEvaluationSummary(
            total_checks=len(checks),
            met_checks=met_checks,
            missed_checks=missed_checks,
            not_measurable_checks=not_measurable,
        ),
        checks=checks,
    )


def _forecast_confidence(
    *,
    intervals: int,
    history_days: float,
    resolution_events: int,
) -> tuple[ForecastConfidence, list[str]]:
    reasons = [
        f"{intervals} measurable ancestor intervals",
        f"{history_days:.2f} days of observed lineage history",
        f"{resolution_events} observed resolution events",
    ]
    if intervals == 0 or history_days < 1:
        return "insufficient_history", reasons
    if intervals >= 5 and history_days >= 90 and resolution_events >= 5:
        return "high", reasons
    if intervals >= 3 and history_days >= 30 and resolution_events >= 2:
        return "medium", reasons
    return "low", reasons


def forecast_remediation(
    trend: SecurityPostureTrend,
    snapshot: SecurityObjectiveSnapshot,
    evaluation: SecurityObjectiveEvaluation,
    *,
    as_of: datetime,
) -> RemediationForecast:
    moment = _utc(as_of)
    target = _utc(snapshot.document.target_date)
    horizon_days = max(0.0, (target - moment).total_seconds() / 86400)
    samples: list[ForecastInterval] = []
    for baseline, current in zip(trend.points, trend.points[1:], strict=False):
        start = _utc(baseline.completed_at or baseline.created_at)
        end = _utc(current.completed_at or current.created_at)
        elapsed = (end - start).total_seconds() / 86400
        if elapsed <= 0:
            continue
        inflow = current.delta.introduced + current.delta.reopened
        resolved = current.delta.resolved
        samples.append(
            ForecastInterval(
                baseline_scan_id=baseline.scan_id,
                current_scan_id=current.scan_id,
                elapsed_days=round(elapsed, 4),
                introduced=current.delta.introduced,
                reopened=current.delta.reopened,
                resolved=resolved,
                inflow_rate_per_day=round(inflow / elapsed, 4),
                resolution_rate_per_day=round(resolved / elapsed, 4),
            )
        )
    history_days = sum(item.elapsed_days for item in samples)
    total_inflow = sum(item.introduced + item.reopened for item in samples)
    total_resolved = sum(item.resolved for item in samples)
    confidence, reasons = _forecast_confidence(
        intervals=len(samples),
        history_days=history_days,
        resolution_events=trend.remediation.resolution_events,
    )
    current_active = trend.remediation.currently_active_fingerprints
    target_active = snapshot.document.max_confirmed_findings
    assumptions = [
        "Forecast uses only the selected scan's direct ancestor chain.",
        "Changed evidence remains one continuous finding and is not counted as inflow or resolution.",
        "Future introduction and resolution rates are assumed to match observed aggregate lineage rates.",
        "The forecast does not execute repository code or call an external model.",
    ]

    if evaluation.met:
        return RemediationForecast(
            status="met",
            confidence=confidence,
            as_of=moment,
            target_date=target,
            horizon_days=round(horizon_days, 2),
            history_generations=len(trend.points),
            history_intervals=len(samples),
            history_days=round(history_days, 2),
            current_active_findings=current_active,
            target_active_findings=target_active,
            introduction_rate_per_day=None,
            resolution_rate_per_day=None,
            net_burn_rate_per_day=None,
            required_resolution_rate_per_day=0.0,
            projected_active_findings=float(current_active),
            projected_net_change=0.0,
            projected_clear_date=moment if current_active == 0 else None,
            confidence_reasons=reasons,
            assumptions=assumptions,
            intervals=samples,
        )
    if horizon_days <= 0:
        return RemediationForecast(
            status="missed",
            confidence=confidence,
            as_of=moment,
            target_date=target,
            horizon_days=0.0,
            history_generations=len(trend.points),
            history_intervals=len(samples),
            history_days=round(history_days, 2),
            current_active_findings=current_active,
            target_active_findings=target_active,
            introduction_rate_per_day=None,
            resolution_rate_per_day=None,
            net_burn_rate_per_day=None,
            required_resolution_rate_per_day=None,
            projected_active_findings=float(current_active),
            projected_net_change=0.0,
            projected_clear_date=None,
            confidence_reasons=reasons,
            assumptions=assumptions,
            intervals=samples,
        )
    if confidence == "insufficient_history":
        return RemediationForecast(
            status="insufficient_history",
            confidence=confidence,
            as_of=moment,
            target_date=target,
            horizon_days=round(horizon_days, 2),
            history_generations=len(trend.points),
            history_intervals=len(samples),
            history_days=round(history_days, 2),
            current_active_findings=current_active,
            target_active_findings=target_active,
            introduction_rate_per_day=None,
            resolution_rate_per_day=None,
            net_burn_rate_per_day=None,
            required_resolution_rate_per_day=None,
            projected_active_findings=None,
            projected_net_change=None,
            projected_clear_date=None,
            confidence_reasons=reasons,
            assumptions=assumptions,
            intervals=samples,
        )

    introduction_rate = total_inflow / history_days
    resolution_rate = total_resolved / history_days
    net_burn_rate = resolution_rate - introduction_rate
    required_rate = introduction_rate + max(0, current_active - target_active) / horizon_days
    projected = max(0.0, current_active + introduction_rate * horizon_days - resolution_rate * horizon_days)
    projected_change = projected - current_active
    projected_clear_date = (
        moment + timedelta(days=current_active / net_burn_rate)
        if current_active > 0 and net_burn_rate > 0
        else (moment if current_active == 0 else None)
    )
    enough_confidence = (
        CONFIDENCE_ORDER[confidence]
        >= CONFIDENCE_ORDER[snapshot.document.minimum_forecast_confidence]
    )
    if projected <= target_active:
        status = "on_track" if enough_confidence else "at_risk"
    else:
        tolerance = max(1.0, current_active * 0.2)
        status = "at_risk" if projected <= target_active + tolerance else "off_track"
    return RemediationForecast(
        status=status,
        confidence=confidence,
        as_of=moment,
        target_date=target,
        horizon_days=round(horizon_days, 2),
        history_generations=len(trend.points),
        history_intervals=len(samples),
        history_days=round(history_days, 2),
        current_active_findings=current_active,
        target_active_findings=target_active,
        introduction_rate_per_day=round(introduction_rate, 4),
        resolution_rate_per_day=round(resolution_rate, 4),
        net_burn_rate_per_day=round(net_burn_rate, 4),
        required_resolution_rate_per_day=round(required_rate, 4),
        projected_active_findings=round(projected, 2),
        projected_net_change=round(projected_change, 2),
        projected_clear_date=projected_clear_date,
        confidence_reasons=reasons,
        assumptions=assumptions,
        intervals=samples,
    )


async def build_security_objective_report(
    db: AsyncSession,
    scan: Scan,
    *,
    posture: SecurityPostureTrend | None = None,
    preview_document: SecurityObjectiveDocument | None = None,
    generated_at: datetime | None = None,
) -> SecurityObjectiveReport:
    profile = await ensure_security_objective(db, scan)
    snapshot = (
        SecurityObjectiveSnapshot(
            profile_id="preview",
            root_scan_id=profile.root_scan_id,
            version=0,
            source="preview",
            objective_sha256=objective_sha256(preview_document),
            document=preview_document,
        )
        if preview_document is not None
        else snapshot_from_profile(profile)
    )
    active_posture = posture or await build_security_posture_trend(db, scan)
    as_of = _scan_moment(scan)
    evaluation = evaluate_security_objective(active_posture, snapshot, as_of=as_of)
    forecast = forecast_remediation(active_posture, snapshot, evaluation, as_of=as_of)
    return SecurityObjectiveReport(
        objective_engine_version=OBJECTIVE_ENGINE_VERSION,
        forecast_engine_version=FORECAST_ENGINE_VERSION,
        generated_at=_utc(generated_at or datetime.now(UTC)),
        scan_id=scan.id,
        root_scan_id=snapshot.root_scan_id,
        objective_profile_id=snapshot.profile_id,
        objective_version=snapshot.version,
        objective_sha256=snapshot.objective_sha256,
        objective_name=snapshot.document.objective_name,
        evaluation=evaluation,
        forecast=forecast,
    )


async def preview_security_objective(
    db: AsyncSession,
    scan: Scan,
    document: SecurityObjectiveDocument,
) -> SecurityObjectivePreview:
    report = await build_security_objective_report(db, scan, preview_document=document)
    return SecurityObjectivePreview(
        scan_id=scan.id,
        objective_sha256=objective_sha256(document),
        report=report,
    )
