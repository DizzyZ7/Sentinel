from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from statistics import mean, median

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.finding import Finding
from app.models.lineage import ScanLineage
from app.models.scan import Scan
from app.schemas.security_posture import (
    RecurrenceItem,
    RemediationEffectiveness,
    RemediationEpisode,
    SecurityPostureDelta,
    SecurityPosturePoint,
    SecurityPostureTrend,
    SecurityPostureTrendSummary,
    TrendDirection,
)
from app.services.comparison import compare_findings, finding_fingerprint
from app.services.project_context import load_context_snapshot
from app.services.risk_exception import evaluate_exception_aware_compliance, list_root_exceptions
from app.services.risk_intelligence import build_executive_report, build_risk_intelligence
from app.services.security_policy import (
    ensure_security_policy,
    evaluate_security_policy,
    load_policy_snapshot,
)
from app.services.security_sla import build_security_debt_dashboard

POSTURE_ENGINE_VERSION = "sentinel-security-posture-v1"


@dataclass(slots=True)
class _EpisodeState:
    fingerprint: str
    rule_id: str
    title: str
    file_path: str
    first_seen_scan_id: str
    first_seen_at: datetime
    due_at: datetime | None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _scan_moment(scan: Scan) -> datetime:
    return _utc(scan.completed_at or scan.created_at)


def _scan_query(scan_ids: list[str]):
    return (
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
            selectinload(Scan.findings).selectinload(Finding.risk_intelligence),
        )
        .where(Scan.id.in_(scan_ids))
    )


async def load_ancestor_chain(db: AsyncSession, current: Scan) -> list[tuple[Scan, ScanLineage | None]]:
    lineage_by_id: dict[str, ScanLineage] = {}
    ordered_ids: list[str] = []
    scan_id: str | None = current.id
    while scan_id is not None:
        ordered_ids.append(scan_id)
        lineage = await db.get(ScanLineage, scan_id)
        if lineage is None:
            break
        lineage_by_id[scan_id] = lineage
        scan_id = lineage.parent_scan_id
    ordered_ids.reverse()
    result = await db.execute(_scan_query(ordered_ids))
    scans = {item.id: item for item in result.scalars()}
    chain = [(scans[item], lineage_by_id.get(item)) for item in ordered_ids if item in scans]
    if not chain:
        return [(current, None)]
    return chain


async def _governance_snapshot(
    db: AsyncSession,
    scan: Scan,
    root_scan_id: str,
    *,
    at: datetime,
):
    await ensure_security_policy(db, scan)
    policy = await load_policy_snapshot(db, scan.id)
    context = await load_context_snapshot(db, scan.id)
    if policy is None:
        raise ValueError("Assigned security policy profile is missing")
    raw = evaluate_security_policy(scan.id, list(scan.findings), policy, context)
    exceptions = await list_root_exceptions(db, root_scan_id)
    governance = evaluate_exception_aware_compliance(
        scan.id,
        list(scan.findings),
        raw,
        exceptions,
        at=at,
    )
    debt = await build_security_debt_dashboard(db, scan, governance=governance, at=at)
    executive = build_executive_report(scan.id, list(scan.findings), context)
    return raw, governance, debt, executive


def _direction(previous: SecurityPosturePoint | None, current: SecurityPosturePoint) -> TrendDirection:
    if previous is None:
        return "insufficient_history"
    worsening = (
        current.policy_blockers > previous.policy_blockers
        or current.sla_overdue > previous.sla_overdue
        or current.posture_score >= previous.posture_score + 5
        or current.confirmed_findings > previous.confirmed_findings
    )
    improving = (
        current.policy_blockers < previous.policy_blockers
        or current.sla_overdue < previous.sla_overdue
        or current.posture_score <= previous.posture_score - 5
        or current.confirmed_findings < previous.confirmed_findings
    )
    if worsening and not improving:
        return "worsening"
    if improving and not worsening:
        return "improving"
    return "stable"


def _metadata(finding: Finding) -> tuple[str, str, str]:
    return finding.rule_id, finding.title, finding.file_path


def _tracked_findings(findings: list[Finding]) -> list[Finding]:
    return [
        item
        for item in findings
        if (item.confirmed is True and item.severity is not None)
        or (item.llm_status in {"pending", "failed", "skipped"} and item.static_confidence >= 0.9)
    ]


def _risk_values(findings: list[Finding]) -> list[float]:
    values: list[float] = []
    for finding in findings:
        if not finding.confirmed or not finding.severity:
            continue
        risk = finding.risk_intelligence or build_risk_intelligence(finding)
        if risk is not None:
            values.append(float(risk.residual_risk_score))
    return values


async def build_security_posture_trend(
    db: AsyncSession,
    current: Scan,
    *,
    generated_at: datetime | None = None,
) -> SecurityPostureTrend:
    chain = await load_ancestor_chain(db, current)
    root_scan_id = chain[0][1].root_scan_id if chain[0][1] else chain[0][0].id
    points: list[SecurityPosturePoint] = []
    previous_tracked: list[Finding] | None = None
    previous_point: SecurityPosturePoint | None = None
    previous_fingerprints: dict[str, Finding] = {}
    active: dict[str, _EpisodeState] = {}
    seen: dict[str, _EpisodeState] = {}
    recurrence_counts: dict[str, int] = {}
    recurrence_last: dict[str, tuple[str, datetime, Finding]] = {}
    episodes: list[RemediationEpisode] = []
    ever_resolved: set[str] = set()

    for scan, lineage in chain:
        moment = _scan_moment(scan)
        raw, governance, debt, executive = await _governance_snapshot(
            db,
            scan,
            root_scan_id,
            at=moment,
        )
        findings = list(scan.findings)
        tracked = _tracked_findings(findings)
        current_fingerprints = {finding_fingerprint(item): item for item in tracked}
        debt_by_fingerprint = {item.fingerprint: item for item in debt.findings}
        delta_items = compare_findings(previous_tracked, tracked) if previous_tracked is not None else []
        delta_counts = {
            state: sum(item.state == state for item in delta_items)
            for state in ("introduced", "resolved", "changed", "persistent")
        }
        changed_pairs = [item for item in delta_items if item.state == "changed" and item.baseline and item.current]
        changed_before = {item.baseline.fingerprint for item in changed_pairs}
        changed_after = {item.current.fingerprint for item in changed_pairs}

        for item in changed_pairs:
            before = item.baseline.fingerprint
            after = item.current.fingerprint
            episode = active.pop(before, None)
            current_finding = current_fingerprints.get(after)
            if episode is not None and current_finding is not None:
                rule_id, title, file_path = _metadata(current_finding)
                transferred = _EpisodeState(
                    fingerprint=after,
                    rule_id=rule_id,
                    title=title,
                    file_path=file_path,
                    first_seen_scan_id=episode.first_seen_scan_id,
                    first_seen_at=episode.first_seen_at,
                    due_at=episode.due_at,
                )
                active[after] = transferred
                seen.setdefault(after, transferred)

        reopened_this_scan = 0
        for fingerprint, finding in current_fingerprints.items():
            if fingerprint in previous_fingerprints or fingerprint in changed_after:
                if fingerprint in active:
                    sla = debt_by_fingerprint.get(fingerprint)
                    if sla is not None:
                        active[fingerprint].due_at = _utc(sla.due_at)
                continue
            sla = debt_by_fingerprint.get(fingerprint)
            due_at = _utc(sla.due_at) if sla is not None else None
            rule_id, title, file_path = _metadata(finding)
            if fingerprint in seen:
                reopened_this_scan += 1
                recurrence_counts[fingerprint] = recurrence_counts.get(fingerprint, 0) + 1
                recurrence_last[fingerprint] = (scan.id, moment, finding)
            episode = _EpisodeState(
                fingerprint=fingerprint,
                rule_id=rule_id,
                title=title,
                file_path=file_path,
                first_seen_scan_id=scan.id,
                first_seen_at=moment,
                due_at=due_at,
            )
            active[fingerprint] = episode
            seen.setdefault(fingerprint, episode)

        for fingerprint in set(previous_fingerprints) - set(current_fingerprints):
            if fingerprint in changed_before:
                continue
            episode = active.pop(fingerprint, None)
            if episode is None:
                continue
            resolution_hours = round(max(0.0, (moment - episode.first_seen_at).total_seconds() / 3600), 2)
            within_sla = moment <= episode.due_at if episode.due_at is not None else None
            episodes.append(
                RemediationEpisode(
                    fingerprint=fingerprint,
                    rule_id=episode.rule_id,
                    title=episode.title,
                    file_path=episode.file_path,
                    first_seen_scan_id=episode.first_seen_scan_id,
                    first_seen_at=episode.first_seen_at,
                    resolved_scan_id=scan.id,
                    resolved_at=moment,
                    resolution_hours=resolution_hours,
                    due_at=episode.due_at,
                    resolved_within_sla=within_sla,
                )
            )
            ever_resolved.add(fingerprint)

        risks = _risk_values(findings)
        point = SecurityPosturePoint(
            scan_id=scan.id,
            parent_scan_id=lineage.parent_scan_id if lineage else None,
            root_scan_id=root_scan_id,
            generation=lineage.generation if lineage else 0,
            created_at=_utc(scan.created_at),
            completed_at=_utc(scan.completed_at) if scan.completed_at else None,
            candidate_count=scan.candidate_count,
            confirmed_findings=sum(item.confirmed is True for item in findings),
            dismissed_candidates=sum(item.confirmed is False for item in findings),
            unreviewed_candidates=sum(item.llm_status in {"pending", "failed", "skipped"} for item in findings),
            verified_remediations=sum(
                item.confirmed
                and item.patch_valid is True
                and item.verification is not None
                and item.verification.status == "passed"
                and item.decision is not None
                and item.decision.decision == "approved"
                for item in findings
            ),
            release_gate_state=executive.gate.state,
            policy_state=raw.state,
            governance_state=governance.state,
            sla_state=debt.state,
            policy_blockers=raw.summary.blocking_findings,
            accepted_risk_findings=governance.summary.accepted_risk_findings,
            sla_at_risk=debt.summary.at_risk,
            sla_overdue=debt.summary.overdue,
            posture_score=executive.summary.posture_score,
            posture_state=executive.summary.posture_state,
            residual_risk_total=round(sum(risks), 1),
            residual_risk_average=round(mean(risks), 1) if risks else 0.0,
            residual_risk_max=round(max(risks), 1) if risks else 0.0,
            delta=SecurityPostureDelta(
                introduced=len(current_fingerprints) if previous_tracked is None else delta_counts["introduced"],
                resolved=delta_counts["resolved"],
                changed=delta_counts["changed"],
                persistent=delta_counts["persistent"],
                reopened=reopened_this_scan,
            ),
            direction="insufficient_history",
        )
        point.direction = _direction(previous_point, point)
        points.append(point)
        previous_tracked = tracked
        previous_point = point
        previous_fingerprints = current_fingerprints

    recurrences: list[RecurrenceItem] = []
    for fingerprint, count in recurrence_counts.items():
        first = seen[fingerprint]
        last_scan_id, last_at, last_finding = recurrence_last[fingerprint]
        recurrences.append(
            RecurrenceItem(
                fingerprint=fingerprint,
                rule_id=last_finding.rule_id,
                title=last_finding.title,
                file_path=last_finding.file_path,
                first_seen_scan_id=first.first_seen_scan_id,
                first_seen_at=first.first_seen_at,
                last_reopened_scan_id=last_scan_id,
                last_reopened_at=last_at,
                recurrence_count=count,
                current_active=fingerprint in active,
            )
        )
    recurrences.sort(key=lambda item: (-item.recurrence_count, item.file_path, item.rule_id))
    episodes.sort(key=lambda item: (item.resolved_at, item.file_path, item.rule_id))
    durations = [item.resolution_hours for item in episodes]
    resolved_within_sla = sum(item.resolved_within_sla is True for item in episodes)
    resolved_after_sla = sum(item.resolved_within_sla is False for item in episodes)
    measurable_sla = resolved_within_sla + resolved_after_sla
    reopened_events = sum(recurrence_counts.values())
    resolved_fingerprints = {item.fingerprint for item in episodes}
    remediation = RemediationEffectiveness(
        resolution_events=len(episodes),
        reopened_events=reopened_events,
        recurrence_rate=(
            round(len(recurrence_counts) / len(resolved_fingerprints) * 100, 1)
            if resolved_fingerprints
            else 0.0
        ),
        mean_resolution_hours=round(mean(durations), 2) if durations else None,
        median_resolution_hours=round(median(durations), 2) if durations else None,
        resolved_within_sla=resolved_within_sla,
        resolved_after_sla=resolved_after_sla,
        sla_attainment_rate=(round(resolved_within_sla / measurable_sla * 100, 1) if measurable_sla else None),
        currently_active_fingerprints=len(active),
        currently_resolved_fingerprints=len(ever_resolved - set(active)),
        episodes=episodes,
        recurrences=recurrences,
    )
    first = points[0]
    last = points[-1]
    trend_direction = last.direction if len(points) > 1 else "insufficient_history"
    summary = SecurityPostureTrendSummary(
        generations=len(points),
        trend_direction=trend_direction,
        current_posture_score=last.posture_score,
        current_posture_state=last.posture_state,
        current_release_gate_state=last.release_gate_state,
        current_governance_state=last.governance_state,
        current_sla_state=last.sla_state,
        confirmed_delta=last.confirmed_findings - first.confirmed_findings,
        posture_score_delta=round(last.posture_score - first.posture_score, 1),
        policy_blocker_delta=last.policy_blockers - first.policy_blockers,
        overdue_delta=last.sla_overdue - first.sla_overdue,
        total_introduced=sum(item.delta.introduced for item in points[1:]),
        total_resolved=sum(item.delta.resolved for item in points[1:]),
        total_changed=sum(item.delta.changed for item in points[1:]),
        total_reopened=sum(item.delta.reopened for item in points[1:]),
    )
    return SecurityPostureTrend(
        engine_version=POSTURE_ENGINE_VERSION,
        generated_at=_utc(generated_at or datetime.now(UTC)),
        root_scan_id=root_scan_id,
        current_scan_id=current.id,
        summary=summary,
        remediation=remediation,
        points=points,
    )
