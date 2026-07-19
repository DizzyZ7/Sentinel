from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.version import APP_VERSION
from app.models.finding import Finding
from app.models.lineage import ScanLineage
from app.models.portfolio import PortfolioGovernanceProfile, PortfolioMember, SecurityPortfolio
from app.models.scan import Scan
from app.schemas.portfolio import (
    PortfolioCheck,
    PortfolioCreate,
    PortfolioDashboard,
    PortfolioEvidenceBundle,
    PortfolioGovernanceDocument,
    PortfolioGovernanceProfileResponse,
    PortfolioGovernanceStatus,
    PortfolioIntegrity,
    PortfolioMemberInput,
    PortfolioMemberResponse,
    PortfolioMemberSnapshot,
    PortfolioResponse,
    PortfolioSummary,
    PortfolioUpdate,
    RiskConcentration,
)
from app.services.security_objective import (
    FORECAST_ENGINE_VERSION,
    OBJECTIVE_ENGINE_VERSION,
    build_security_objective_report,
)
from app.services.security_posture import POSTURE_ENGINE_VERSION, build_security_posture_trend

PORTFOLIO_ENGINE_VERSION = "sentinel-portfolio-governance-v1"
CRITICALITY_WEIGHTS = {"low": 1, "medium": 2, "high": 3, "critical": 4}


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


def governance_sha256(document: PortfolioGovernanceDocument) -> str:
    return _sha256(document.model_dump(mode="json"))


def default_portfolio_governance() -> PortfolioGovernanceDocument:
    return PortfolioGovernanceDocument()


async def _portfolio(db: AsyncSession, portfolio_id: str) -> SecurityPortfolio | None:
    return await db.get(SecurityPortfolio, portfolio_id)


async def _members(db: AsyncSession, portfolio_id: str) -> list[PortfolioMember]:
    result = await db.execute(
        select(PortfolioMember)
        .where(PortfolioMember.portfolio_id == portfolio_id)
        .order_by(PortfolioMember.criticality.desc(), PortfolioMember.display_name)
    )
    return list(result.scalars())


def _member_response(member: PortfolioMember) -> PortfolioMemberResponse:
    return PortfolioMemberResponse(
        root_scan_id=member.root_scan_id,
        pinned_scan_id=member.pinned_scan_id,
        display_name=member.display_name,
        business_unit=member.business_unit,
        criticality=member.criticality,
        added_at=member.added_at,
    )


async def portfolio_response(db: AsyncSession, portfolio: SecurityPortfolio) -> PortfolioResponse:
    return PortfolioResponse(
        portfolio_id=portfolio.id,
        name=portfolio.name,
        description=portfolio.description,
        created_at=portfolio.created_at,
        updated_at=portfolio.updated_at,
        members=[_member_response(item) for item in await _members(db, portfolio.id)],
    )


async def _validate_member(db: AsyncSession, item: PortfolioMemberInput) -> None:
    root = await db.get(Scan, item.root_scan_id)
    if root is None:
        raise ValueError("Portfolio root scan not found")
    lineage = await db.get(ScanLineage, item.root_scan_id)
    if lineage is not None and lineage.root_scan_id != item.root_scan_id:
        raise ValueError("root_scan_id must identify a lineage root")
    if item.pinned_scan_id is not None:
        pinned = await db.get(Scan, item.pinned_scan_id)
        if pinned is None:
            raise ValueError("Pinned scan not found")
        pinned_lineage = await db.get(ScanLineage, item.pinned_scan_id)
        pinned_root = pinned_lineage.root_scan_id if pinned_lineage else pinned.id
        if pinned_root != item.root_scan_id:
            raise ValueError("Pinned scan must belong to the selected root lineage")


async def create_portfolio(db: AsyncSession, request: PortfolioCreate) -> SecurityPortfolio:
    portfolio = SecurityPortfolio(name=request.name, description=request.description)
    db.add(portfolio)
    await db.flush()
    document = request.governance or default_portfolio_governance()
    db.add(
        PortfolioGovernanceProfile(
            portfolio_id=portfolio.id,
            version=1,
            source="declared" if request.governance is not None else "built_in",
            governance_sha256=governance_sha256(document),
            document=document.model_dump(mode="json"),
        )
    )
    for item in request.members:
        await _validate_member(db, item)
        db.add(
            PortfolioMember(
                portfolio_id=portfolio.id,
                root_scan_id=item.root_scan_id,
                pinned_scan_id=item.pinned_scan_id,
                display_name=item.display_name,
                business_unit=item.business_unit,
                criticality=item.criticality,
            )
        )
    await db.flush()
    return portfolio


async def list_portfolios(db: AsyncSession) -> list[PortfolioResponse]:
    result = await db.execute(select(SecurityPortfolio).order_by(SecurityPortfolio.created_at.desc()))
    return [await portfolio_response(db, item) for item in result.scalars()]


async def update_portfolio(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    request: PortfolioUpdate,
) -> SecurityPortfolio:
    if request.name is not None:
        portfolio.name = request.name
    if "description" in request.model_fields_set:
        portfolio.description = request.description
    portfolio.updated_at = datetime.now(UTC)
    await db.flush()
    return portfolio


async def upsert_portfolio_member(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    request: PortfolioMemberInput,
) -> PortfolioMember:
    await _validate_member(db, request)
    member = await db.get(PortfolioMember, (portfolio.id, request.root_scan_id))
    if member is None:
        member = PortfolioMember(portfolio_id=portfolio.id, root_scan_id=request.root_scan_id)
        db.add(member)
    member.pinned_scan_id = request.pinned_scan_id
    member.display_name = request.display_name
    member.business_unit = request.business_unit
    member.criticality = request.criticality
    portfolio.updated_at = datetime.now(UTC)
    await db.flush()
    return member


async def remove_portfolio_member(db: AsyncSession, portfolio_id: str, root_scan_id: str) -> bool:
    result = await db.execute(
        delete(PortfolioMember).where(
            PortfolioMember.portfolio_id == portfolio_id,
            PortfolioMember.root_scan_id == root_scan_id,
        )
    )
    return bool(result.rowcount)


async def _governance_profiles(db: AsyncSession, portfolio_id: str) -> list[PortfolioGovernanceProfile]:
    result = await db.execute(
        select(PortfolioGovernanceProfile)
        .where(PortfolioGovernanceProfile.portfolio_id == portfolio_id)
        .order_by(PortfolioGovernanceProfile.version)
    )
    return list(result.scalars())


def _governance_response(
    profile: PortfolioGovernanceProfile,
    latest_version: int,
) -> PortfolioGovernanceProfileResponse:
    return PortfolioGovernanceProfileResponse(
        profile_id=profile.id,
        portfolio_id=profile.portfolio_id,
        version=profile.version,
        source=profile.source,
        governance_sha256=profile.governance_sha256,
        document=PortfolioGovernanceDocument.model_validate(profile.document),
        created_at=profile.created_at,
        latest=profile.version == latest_version,
    )


async def governance_status(db: AsyncSession, portfolio_id: str) -> PortfolioGovernanceStatus:
    profiles = await _governance_profiles(db, portfolio_id)
    if not profiles:
        raise ValueError("Portfolio governance profile is missing")
    latest = profiles[-1]
    return PortfolioGovernanceStatus(
        portfolio_id=portfolio_id,
        latest_profile=_governance_response(latest, latest.version),
        versions=[_governance_response(item, latest.version) for item in profiles],
    )


async def create_governance_version(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    document: PortfolioGovernanceDocument,
) -> PortfolioGovernanceProfile:
    profiles = await _governance_profiles(db, portfolio.id)
    digest = governance_sha256(document)
    if profiles and profiles[-1].governance_sha256 == digest:
        return profiles[-1]
    result = await db.execute(
        select(func.max(PortfolioGovernanceProfile.version)).where(
            PortfolioGovernanceProfile.portfolio_id == portfolio.id
        )
    )
    profile = PortfolioGovernanceProfile(
        portfolio_id=portfolio.id,
        version=(result.scalar_one() or 0) + 1,
        source="declared",
        governance_sha256=digest,
        document=document.model_dump(mode="json"),
    )
    db.add(profile)
    portfolio.updated_at = datetime.now(UTC)
    await db.flush()
    return profile


def _scan_query(scan_id: str):
    return (
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
            selectinload(Scan.findings).selectinload(Finding.risk_intelligence),
        )
        .where(Scan.id == scan_id)
    )


async def _lineage_heads(db: AsyncSession, root_scan_id: str) -> list[ScanLineage]:
    result = await db.execute(
        select(ScanLineage)
        .where(ScanLineage.root_scan_id == root_scan_id)
        .order_by(ScanLineage.generation.desc(), ScanLineage.created_at.desc())
    )
    rows = list(result.scalars())
    if not rows:
        return []
    parents = {item.parent_scan_id for item in rows if item.parent_scan_id is not None}
    return [item for item in rows if item.scan_id not in parents]


async def _selected_scan(
    db: AsyncSession,
    member: PortfolioMember,
) -> tuple[Scan | None, int, bool]:
    heads = await _lineage_heads(db, member.root_scan_id)
    if member.pinned_scan_id is not None:
        selected_id = member.pinned_scan_id
        ambiguous = False
    elif heads:
        selected_id = heads[0].scan_id
        ambiguous = len(heads) > 1
    else:
        selected_id = member.root_scan_id
        ambiguous = False
    result = await db.execute(_scan_query(selected_id))
    return result.scalar_one_or_none(), max(len(heads), 1), ambiguous


def _readiness(snapshot: PortfolioMemberSnapshot) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if snapshot.evidence_state != "current":
        reasons.append(f"Evidence state is {snapshot.evidence_state}.")
        return "blocked", reasons
    for label, value in (
        ("release gate", snapshot.release_gate_state),
        ("security policy", snapshot.policy_state),
    ):
        if value == "blocked":
            reasons.append(f"{label.title()} is blocked.")
    if snapshot.governance_state == "blocked":
        reasons.append("Exception-aware governance is blocked.")
    if snapshot.sla_overdue and snapshot.sla_overdue > 0:
        reasons.append(f"{snapshot.sla_overdue} SLA findings are overdue.")
    if snapshot.objective_state == "missed":
        reasons.append("The assigned security objective is missed.")
    if snapshot.forecast_status in {"off_track", "missed"}:
        reasons.append(f"Remediation forecast is {snapshot.forecast_status}.")
    if reasons:
        return "blocked", reasons
    if snapshot.governance_state == "accepted_risk":
        reasons.append("Governance currently relies on accepted risk.")
    if snapshot.sla_at_risk and snapshot.sla_at_risk > 0:
        reasons.append(f"{snapshot.sla_at_risk} SLA findings are at risk.")
    if snapshot.objective_state in {"at_risk", "insufficient_history"}:
        reasons.append(f"Objective state is {snapshot.objective_state}.")
    if snapshot.forecast_status in {"at_risk", "insufficient_history"}:
        reasons.append(f"Forecast state is {snapshot.forecast_status}.")
    return ("at_risk", reasons) if reasons else ("passed", [])


async def _member_snapshot(
    db: AsyncSession,
    member: PortfolioMember,
    governance: PortfolioGovernanceDocument,
    *,
    generated_at: datetime,
) -> PortfolioMemberSnapshot:
    scan, head_count, ambiguous = await _selected_scan(db, member)
    base = dict(
        root_scan_id=member.root_scan_id,
        scan_id=scan.id if scan else None,
        display_name=member.display_name,
        business_unit=member.business_unit,
        criticality=member.criticality,
        weight=CRITICALITY_WEIGHTS[member.criticality],
        pinned=member.pinned_scan_id is not None,
        branch_heads=head_count,
        scan_status=scan.status if scan else None,
    )
    if scan is None:
        return PortfolioMemberSnapshot(
            **base,
            evidence_state="missing",
            readiness="blocked",
            reasons=["No scan evidence exists."],
        )
    if ambiguous:
        return PortfolioMemberSnapshot(
            **base,
            evidence_state="ambiguous_head",
            readiness="blocked",
            reasons=[f"Lineage has {head_count} unpinned branch heads."],
        )
    if scan.status == "failed":
        return PortfolioMemberSnapshot(
            **base,
            evidence_state="failed",
            readiness="blocked",
            reasons=["Latest selected scan failed."],
        )
    if scan.status != "completed":
        return PortfolioMemberSnapshot(
            **base,
            evidence_state="in_progress",
            readiness="blocked",
            reasons=[f"Latest selected scan is {scan.status}."],
        )
    completed = _utc(scan.completed_at or scan.created_at)
    age_days = max(0.0, (generated_at - completed).total_seconds() / 86400)
    evidence_state = "stale" if age_days > governance.max_scan_age_days else "current"
    posture = await build_security_posture_trend(db, scan, generated_at=generated_at)
    objective = await build_security_objective_report(db, scan, posture=posture, generated_at=generated_at)
    current = posture.points[-1]
    snapshot = PortfolioMemberSnapshot(
        **base,
        evidence_state=evidence_state,
        evidence_age_days=round(age_days, 2),
        readiness="passed",
        posture_score=current.posture_score,
        posture_state=current.posture_state,
        residual_risk_total=current.residual_risk_total,
        confirmed_findings=current.confirmed_findings,
        policy_blockers=current.policy_blockers,
        accepted_risk_findings=current.accepted_risk_findings,
        sla_at_risk=current.sla_at_risk,
        sla_overdue=current.sla_overdue,
        release_gate_state=current.release_gate_state,
        policy_state=current.policy_state,
        governance_state=current.governance_state,
        objective_state=objective.evaluation.state,
        forecast_status=objective.forecast.status,
        forecast_confidence=objective.forecast.confidence,
        projected_active_findings=objective.forecast.projected_active_findings,
        objective_target_date=objective.evaluation.target_date,
    )
    readiness, reasons = _readiness(snapshot)
    snapshot.readiness = readiness
    snapshot.reasons = reasons
    return snapshot


def _numeric_check(key: str, label: str, actual: float | int, target: float | int) -> PortfolioCheck:
    met = actual <= target
    return PortfolioCheck(
        key=key,
        label=label,
        operator="<=",
        target=target,
        actual=actual,
        status="met" if met else "missed",
        explanation=f"Actual {actual} <= target {target}: {'met' if met else 'missed'}.",
    )


def _boolean_check(key: str, label: str, actual: bool) -> PortfolioCheck:
    return PortfolioCheck(
        key=key,
        label=label,
        operator="==",
        target=True,
        actual=actual,
        status="met" if actual else "missed",
        explanation=f"{label} is {'satisfied' if actual else 'not satisfied'}.",
    )


async def build_portfolio_dashboard(
    db: AsyncSession,
    portfolio: SecurityPortfolio,
    *,
    generated_at: datetime | None = None,
) -> PortfolioDashboard:
    moment = _utc(generated_at or datetime.now(UTC))
    status = await governance_status(db, portfolio.id)
    governance = status.latest_profile
    members = [
        await _member_snapshot(db, item, governance.document, generated_at=moment)
        for item in await _members(db, portfolio.id)
    ]
    total_weight = sum(item.weight for item in members if item.posture_score is not None)
    weighted_posture = (
        sum((item.posture_score or 0.0) * item.weight for item in members if item.posture_score is not None)
        / total_weight
        if total_weight
        else None
    )
    weighted_risk_by_member = [
        (item, (item.residual_risk_total or 0.0) * item.weight)
        for item in members
        if item.residual_risk_total is not None
    ]
    weighted_risk = sum(value for _, value in weighted_risk_by_member)
    concentrations = [
        RiskConcentration(
            root_scan_id=item.root_scan_id,
            display_name=item.display_name,
            weighted_residual_risk=round(value, 2),
            share_percent=round(value / weighted_risk * 100, 2) if weighted_risk else 0.0,
        )
        for item, value in sorted(weighted_risk_by_member, key=lambda pair: pair[1], reverse=True)
    ]
    top_concentration = concentrations[0].share_percent if concentrations else 0.0
    def count(predicate):
        return sum(1 for item in members if predicate(item))
    missing_members = count(lambda item: item.evidence_state == "missing")
    stale_members = count(lambda item: item.evidence_state == "stale")
    unavailable_members = count(lambda item: item.evidence_state in {"failed", "in_progress"})
    ambiguous_heads = count(lambda item: item.evidence_state == "ambiguous_head")
    blocked_members = count(lambda item: item.readiness == "blocked")
    at_risk_members = count(lambda item: item.readiness == "at_risk")
    release_passed = all(item.release_gate_state == "passed" for item in members if item.scan_id is not None)
    policy_passed = all(item.policy_state == "passed" for item in members if item.scan_id is not None)
    governance_passed = all(item.governance_state == "passed" for item in members if item.scan_id is not None)
    checks = [
        _numeric_check(
            "missing_members",
            "Missing member evidence",
            missing_members,
            governance.document.max_missing_members,
        ),
        _numeric_check(
            "stale_members",
            "Stale member evidence",
            stale_members,
            governance.document.max_stale_members,
        ),
        _numeric_check(
            "unavailable_members",
            "Unavailable member evidence",
            unavailable_members,
            governance.document.max_unavailable_members,
        ),
        _numeric_check(
            "ambiguous_heads",
            "Unpinned ambiguous lineage heads",
            ambiguous_heads,
            governance.document.max_ambiguous_heads,
        ),
        _numeric_check(
            "blocked_members",
            "Blocked member lineages",
            blocked_members,
            governance.document.max_blocked_members,
        ),
        _numeric_check(
            "weighted_posture_score",
            "Criticality-weighted posture score",
            round(weighted_posture or 0.0, 2),
            governance.document.max_weighted_posture_score,
        ),
        _numeric_check(
            "risk_concentration",
            "Largest weighted residual-risk concentration",
            top_concentration,
            governance.document.max_risk_concentration_percent,
        ),
        _numeric_check(
            "overdue_findings",
            "Portfolio overdue SLA findings",
            sum(item.sla_overdue or 0 for item in members),
            governance.document.max_overdue_findings,
        ),
        _numeric_check(
            "accepted_risk_findings",
            "Portfolio accepted-risk findings",
            sum(item.accepted_risk_findings or 0 for item in members),
            governance.document.max_accepted_risk_findings,
        ),
        _numeric_check(
            "missed_objectives",
            "Missed lineage objectives",
            count(lambda item: item.objective_state == "missed"),
            governance.document.max_missed_objectives,
        ),
        _numeric_check(
            "off_track_forecasts",
            "Off-track or missed remediation forecasts",
            count(lambda item: item.forecast_status in {"off_track", "missed"}),
            governance.document.max_off_track_forecasts,
        ),
    ]
    if governance.document.require_all_release_gates_passed:
        checks.append(_boolean_check("release_gates", "All selected release gates pass", release_passed))
    if governance.document.require_all_policies_passed:
        checks.append(_boolean_check("security_policies", "All selected security policies pass", policy_passed))
    if governance.document.require_all_governance_passed:
        checks.append(_boolean_check("exception_governance", "All selected governance states pass", governance_passed))
    missed = [item for item in checks if item.status == "missed"]
    evidence_missed = any(
        item.status == "missed"
        and item.key in {"missing_members", "stale_members", "unavailable_members", "ambiguous_heads"}
        for item in checks
    )
    if not members or evidence_missed:
        state = "insufficient_evidence"
    elif missed:
        state = "blocked"
    elif at_risk_members:
        state = "at_risk"
    else:
        state = "passed"
    reasons = [item.explanation for item in missed]
    if not members:
        reasons.insert(0, "Portfolio has no member lineages.")
    summary = PortfolioSummary(
        state=state,
        total_members=len(members),
        passed_members=count(lambda item: item.readiness == "passed"),
        at_risk_members=at_risk_members,
        blocked_members=blocked_members,
        current_members=count(lambda item: item.evidence_state == "current"),
        stale_members=stale_members,
        missing_members=missing_members,
        unavailable_members=unavailable_members,
        ambiguous_heads=ambiguous_heads,
        confirmed_findings=sum(item.confirmed_findings or 0 for item in members),
        policy_blockers=sum(item.policy_blockers or 0 for item in members),
        accepted_risk_findings=sum(item.accepted_risk_findings or 0 for item in members),
        sla_at_risk=sum(item.sla_at_risk or 0 for item in members),
        sla_overdue=sum(item.sla_overdue or 0 for item in members),
        missed_objectives=count(lambda item: item.objective_state == "missed"),
        at_risk_objectives=count(lambda item: item.objective_state in {"at_risk", "insufficient_history"}),
        off_track_forecasts=count(lambda item: item.forecast_status in {"off_track", "missed"}),
        insufficient_forecasts=count(lambda item: item.forecast_status == "insufficient_history"),
        weighted_posture_score=round(weighted_posture, 2) if weighted_posture is not None else None,
        weighted_residual_risk=round(weighted_risk, 2),
        top_risk_concentration_percent=top_concentration,
        reasons=reasons,
    )
    return PortfolioDashboard(
        engine_version=PORTFOLIO_ENGINE_VERSION,
        generated_at=moment,
        portfolio=await portfolio_response(db, portfolio),
        governance=governance,
        summary=summary,
        checks=checks,
        concentrations=concentrations,
        members=members,
    )


def build_portfolio_evidence(dashboard: PortfolioDashboard) -> PortfolioEvidenceBundle:
    sections: dict[str, Any] = {
        "versions": {
            "app": APP_VERSION,
            "portfolio_engine": PORTFOLIO_ENGINE_VERSION,
            "security_posture_engine": POSTURE_ENGINE_VERSION,
            "security_objective_engine": OBJECTIVE_ENGINE_VERSION,
            "remediation_forecast_engine": FORECAST_ENGINE_VERSION,
        },
        "portfolio": dashboard.portfolio.model_dump(mode="json"),
        "governance": dashboard.governance.model_dump(mode="json"),
        "summary": dashboard.summary.model_dump(mode="json"),
        "checks": [item.model_dump(mode="json") for item in dashboard.checks],
        "concentrations": [item.model_dump(mode="json") for item in dashboard.concentrations],
        "members": [item.model_dump(mode="json") for item in dashboard.members],
    }
    integrity = PortfolioIntegrity(
        section_sha256={key: _sha256(value) for key, value in sections.items()},
        payload_sha256=_sha256(sections),
    )
    return PortfolioEvidenceBundle(
        generated_at=dashboard.generated_at,
        **sections,
        integrity=integrity,
    )
