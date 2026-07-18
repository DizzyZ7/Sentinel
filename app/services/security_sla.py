from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.lineage import ScanLineage
from app.models.scan import Scan
from app.models.security_sla import FindingSLA, ScanSLAAssignment, SecuritySLAProfile
from app.schemas.risk_exception import ExceptionAwareCompliance
from app.schemas.security_sla import (
    FindingSLAResponse,
    SecurityDebtComparison,
    SecurityDebtComparisonSummary,
    SecurityDebtDashboard,
    SecurityDebtSummary,
    SecuritySLADocument,
    SecuritySLAOverride,
    SecuritySLAProfileResponse,
    SecuritySLAStatus,
    TeamDebtSummary,
)
from app.services.comparison import finding_fingerprint
from app.services.project_context import ProjectAssetContext, ProjectContextSnapshot

SLA_ENGINE_VERSION = "sentinel-security-sla-v1"
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True, slots=True)
class SecuritySLASnapshot:
    profile_id: str
    root_scan_id: str
    version: int
    source: str
    sla_sha256: str
    document: SecuritySLADocument


@dataclass(frozen=True, slots=True)
class SLAAssignment:
    due_hours: int
    assigned_team: str
    risk_owner: str
    escalation_contact: str | None
    asset_id: str | None
    matched_override_id: str | None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _now(value: datetime | None = None) -> datetime:
    return _utc(value or datetime.now(UTC))


def sla_sha256(document: SecuritySLADocument) -> str:
    payload = json.dumps(document.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_security_sla(raw: str | None) -> SecuritySLADocument | None:
    if raw is None or not raw.strip():
        return None
    try:
        return SecuritySLADocument.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError(f"Invalid security SLA profile: {exc}") from exc


def default_security_sla() -> SecuritySLADocument:
    return SecuritySLADocument()


def demo_security_sla() -> SecuritySLADocument:
    return SecuritySLADocument(
        profile_name="Sentinel production remediation SLA",
        critical_hours=12,
        high_hours=72,
        medium_hours=336,
        low_hours=1440,
        production_multiplier=0.75,
        public_asset_multiplier=0.5,
        restricted_data_multiplier=0.5,
        critical_asset_multiplier=0.5,
        at_risk_window_hours=24,
        default_team="Application Security",
        default_risk_owner="Security Engineering Lead",
        default_escalation_contact="security-lead@example.invalid",
        overrides=[
            SecuritySLAOverride(
                override_id="customer-data-owner",
                name="Customer data service ownership",
                asset_ids=["customer-data-api"],
                due_hours=24,
                assigned_team="Customer Platform",
                risk_owner="Customer Platform Lead",
                escalation_contact="platform-security@example.invalid",
            ),
            SecuritySLAOverride(
                override_id="inventory-owner",
                name="Inventory query ownership",
                asset_ids=["inventory-query-service"],
                due_hours=72,
                assigned_team="Inventory Services",
                risk_owner="Inventory Engineering Lead",
            ),
        ],
    )


async def _root_scan_id(db: AsyncSession, scan: Scan) -> str:
    lineage = await db.get(ScanLineage, scan.id)
    return lineage.root_scan_id if lineage else scan.id


async def _latest_profile(db: AsyncSession, root_scan_id: str) -> SecuritySLAProfile | None:
    result = await db.execute(
        select(SecuritySLAProfile)
        .where(SecuritySLAProfile.root_scan_id == root_scan_id)
        .order_by(SecuritySLAProfile.version.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _profile(db: AsyncSession, profile_id: str) -> SecuritySLAProfile:
    profile = await db.get(SecuritySLAProfile, profile_id)
    if profile is None:
        raise ValueError("Assigned security SLA profile is missing")
    return profile


def snapshot_from_profile(profile: SecuritySLAProfile) -> SecuritySLASnapshot:
    return SecuritySLASnapshot(
        profile_id=profile.id,
        root_scan_id=profile.root_scan_id,
        version=profile.version,
        source=profile.source,
        sla_sha256=profile.sla_sha256,
        document=SecuritySLADocument.model_validate(profile.document),
    )


async def ensure_security_sla(
    db: AsyncSession,
    scan: Scan,
    document: SecuritySLADocument | None = None,
    *,
    source: str | None = None,
) -> SecuritySLAProfile:
    assignment = await db.get(ScanSLAAssignment, scan.id)
    if assignment:
        return await _profile(db, assignment.profile_id)
    root_scan_id = await _root_scan_id(db, scan)
    latest = await _latest_profile(db, root_scan_id)
    if latest is None:
        active = document or default_security_sla()
        latest = SecuritySLAProfile(
            id=str(uuid.uuid4()),
            root_scan_id=root_scan_id,
            version=1,
            source=source or ("declared" if document is not None else "inferred"),
            sla_sha256=sla_sha256(active),
            document=active.model_dump(mode="json"),
        )
        db.add(latest)
        await db.flush()
    db.add(ScanSLAAssignment(scan_id=scan.id, profile_id=latest.id))
    await db.flush()
    return latest


async def assign_latest_security_sla(
    db: AsyncSession,
    baseline: Scan,
    current: Scan,
) -> SecuritySLAProfile:
    await ensure_security_sla(db, baseline)
    root_scan_id = await _root_scan_id(db, baseline)
    latest = await _latest_profile(db, root_scan_id)
    assert latest is not None
    if await db.get(ScanSLAAssignment, current.id) is None:
        db.add(ScanSLAAssignment(scan_id=current.id, profile_id=latest.id))
        await db.flush()
    return latest


async def load_sla_snapshot(db: AsyncSession, scan_id: str) -> SecuritySLASnapshot | None:
    assignment = await db.get(ScanSLAAssignment, scan_id)
    if assignment is None:
        return None
    return snapshot_from_profile(await _profile(db, assignment.profile_id))


async def create_security_sla_version(
    db: AsyncSession,
    scan: Scan,
    document: SecuritySLADocument,
) -> SecuritySLAProfile:
    root_scan_id = await _root_scan_id(db, scan)
    latest = await _latest_profile(db, root_scan_id)
    digest = sla_sha256(document)
    if latest is not None and latest.sla_sha256 == digest:
        return latest
    result = await db.execute(
        select(func.max(SecuritySLAProfile.version)).where(SecuritySLAProfile.root_scan_id == root_scan_id)
    )
    profile = SecuritySLAProfile(
        id=str(uuid.uuid4()),
        root_scan_id=root_scan_id,
        version=(result.scalar_one() or 0) + 1,
        source="declared",
        sla_sha256=digest,
        document=document.model_dump(mode="json"),
    )
    db.add(profile)
    await db.flush()
    return profile


def _profile_response(profile: SecuritySLAProfile, assigned_id: str) -> SecuritySLAProfileResponse:
    return SecuritySLAProfileResponse(
        profile_id=profile.id,
        root_scan_id=profile.root_scan_id,
        version=profile.version,
        source=profile.source,
        sla_sha256=profile.sla_sha256,
        document=SecuritySLADocument.model_validate(profile.document),
        created_at=profile.created_at,
        assigned_to_current_scan=profile.id == assigned_id,
    )


async def build_security_sla_status(db: AsyncSession, scan: Scan) -> SecuritySLAStatus:
    assigned = await ensure_security_sla(db, scan)
    result = await db.execute(
        select(SecuritySLAProfile)
        .where(SecuritySLAProfile.root_scan_id == assigned.root_scan_id)
        .order_by(SecuritySLAProfile.version)
    )
    profiles = list(result.scalars())
    latest = profiles[-1]
    return SecuritySLAStatus(
        scan_id=scan.id,
        root_scan_id=assigned.root_scan_id,
        assigned_profile=_profile_response(assigned, assigned.id),
        latest_profile=_profile_response(latest, assigned.id),
        versions=[_profile_response(item, assigned.id) for item in profiles],
        next_rescan_uses_version=latest.version,
    )


def _pattern_specificity(pattern: str) -> int:
    return sum(character not in "*?[]" for character in pattern)


def _matching_asset(snapshot: ProjectContextSnapshot | None, file_path: str) -> ProjectAssetContext | None:
    if snapshot is None:
        return None
    normalized = file_path.replace("\\", "/").lstrip("/")
    matches: list[tuple[int, str, ProjectAssetContext]] = []
    for asset in snapshot.document.assets:
        for pattern in asset.path_patterns:
            if fnmatch.fnmatchcase(normalized, pattern) or PurePosixPath(normalized).match(pattern):
                matches.append((_pattern_specificity(pattern), asset.asset_id, asset))
    return sorted(matches, key=lambda item: (-item[0], item[1]))[0][2] if matches else None


def _effective_severity(finding: Finding) -> str | None:
    if finding.confirmed and finding.severity in SEVERITY_ORDER:
        return finding.severity
    if finding.llm_status in {"failed", "skipped", "pending"} and finding.static_confidence >= 0.9:
        return "high"
    return None


def _override_matches(
    override: SecuritySLAOverride,
    finding: Finding,
    *,
    severity: str,
    asset: ProjectAssetContext | None,
    environment: str,
) -> bool:
    if not override.enabled:
        return False
    path = finding.file_path.replace("\\", "/").lstrip("/")
    checks = (
        (override.asset_ids, asset.asset_id if asset else None),
        (override.rule_ids, finding.rule_id),
        (override.severities, severity),
        (override.exposures, asset.exposure if asset else "unknown"),
        (override.data_classifications, asset.data_classification if asset else "internal"),
        (override.criticalities, asset.criticality if asset else "medium"),
        (override.environments, environment),
    )
    if any(values and value not in values for values, value in checks):
        return False
    if override.path_patterns and not any(
        fnmatch.fnmatchcase(path, pattern) or PurePosixPath(path).match(pattern)
        for pattern in override.path_patterns
    ):
        return False
    return any(values for values, _ in checks) or bool(override.path_patterns)


def compute_sla_assignment(
    finding: Finding,
    snapshot: SecuritySLASnapshot,
    context: ProjectContextSnapshot | None,
) -> SLAAssignment | None:
    severity = _effective_severity(finding)
    if severity is None:
        return None
    document = snapshot.document
    asset = _matching_asset(context, finding.file_path)
    environment = context.document.environment if context else "unknown"
    base = {
        "critical": document.critical_hours,
        "high": document.high_hours,
        "medium": document.medium_hours,
        "low": document.low_hours,
    }[severity]
    multiplier = 1.0
    if environment == "production":
        multiplier *= document.production_multiplier
    if asset and asset.exposure == "public":
        multiplier *= document.public_asset_multiplier
    if asset and asset.data_classification == "restricted":
        multiplier *= document.restricted_data_multiplier
    if asset and asset.criticality == "critical":
        multiplier *= document.critical_asset_multiplier
    due_hours = max(1, math.ceil(base * multiplier))
    matched = next(
        (
            item
            for item in document.overrides
            if _override_matches(item, finding, severity=severity, asset=asset, environment=environment)
        ),
        None,
    )
    if matched and matched.due_hours is not None:
        due_hours = matched.due_hours
    asset_owner = asset.owner if asset and asset.owner else None
    return SLAAssignment(
        due_hours=due_hours,
        assigned_team=(
            matched.assigned_team
            if matched and matched.assigned_team
            else asset_owner or document.default_team
        ),
        risk_owner=(
            matched.risk_owner
            if matched and matched.risk_owner
            else asset_owner or document.default_risk_owner
        ),
        escalation_contact=(
            matched.escalation_contact
            if matched and matched.escalation_contact
            else document.default_escalation_contact
        ),
        asset_id=asset.asset_id if asset else None,
        matched_override_id=matched.override_id if matched else None,
    )


async def persist_finding_slas(
    db: AsyncSession,
    scan: Scan,
    context: ProjectContextSnapshot | None,
) -> list[FindingSLA]:
    profile = await ensure_security_sla(db, scan)
    snapshot = snapshot_from_profile(profile)
    root_scan_id = await _root_scan_id(db, scan)
    existing_result = await db.execute(select(FindingSLA).where(FindingSLA.scan_id == scan.id))
    existing_by_finding = {item.finding_id: item for item in existing_result.scalars()}
    prior_result = await db.execute(
        select(FindingSLA)
        .where(FindingSLA.root_scan_id == root_scan_id, FindingSLA.scan_id != scan.id)
        .order_by(FindingSLA.started_at, FindingSLA.id)
    )
    origin_by_fingerprint: dict[str, FindingSLA] = {}
    for item in prior_result.scalars():
        origin_by_fingerprint.setdefault(item.fingerprint, item)
    created: list[FindingSLA] = []
    first_seen = _utc(scan.created_at or datetime.now(UTC))
    for finding in sorted(scan.findings, key=lambda item: (item.file_path, item.line, item.id)):
        if finding.id in existing_by_finding:
            created.append(existing_by_finding[finding.id])
            continue
        assignment = compute_sla_assignment(finding, snapshot, context)
        if assignment is None:
            continue
        fingerprint = finding_fingerprint(finding)
        origin = origin_by_fingerprint.get(fingerprint)
        if origin is not None:
            item = FindingSLA(
                id=str(uuid.uuid4()),
                finding_id=finding.id,
                scan_id=scan.id,
                root_scan_id=root_scan_id,
                profile_id=origin.profile_id,
                origin_sla_id=origin.origin_sla_id or origin.id,
                fingerprint=fingerprint,
                asset_id=origin.asset_id,
                effective_severity=origin.effective_severity,
                assigned_team=origin.assigned_team,
                risk_owner=origin.risk_owner,
                escalation_contact=origin.escalation_contact,
                assignment_source="lineage_inherited",
                matched_override_id=origin.matched_override_id,
                started_at=_utc(origin.started_at),
                at_risk_at=_utc(origin.at_risk_at),
                due_at=_utc(origin.due_at),
            )
        else:
            due_at = first_seen + timedelta(hours=assignment.due_hours)
            at_risk_at = max(first_seen, due_at - timedelta(hours=snapshot.document.at_risk_window_hours))
            item = FindingSLA(
                id=str(uuid.uuid4()),
                finding_id=finding.id,
                scan_id=scan.id,
                root_scan_id=root_scan_id,
                profile_id=profile.id,
                origin_sla_id=None,
                fingerprint=fingerprint,
                asset_id=assignment.asset_id,
                effective_severity=_effective_severity(finding) or "high",
                assigned_team=assignment.assigned_team,
                risk_owner=assignment.risk_owner,
                escalation_contact=assignment.escalation_contact,
                assignment_source="first_seen",
                matched_override_id=assignment.matched_override_id,
                started_at=first_seen,
                at_risk_at=at_risk_at,
                due_at=due_at,
            )
            origin_by_fingerprint[fingerprint] = item
        db.add(item)
        created.append(item)
    await db.flush()
    return created


async def _sla_rows(db: AsyncSession, scan_id: str) -> list[FindingSLA]:
    result = await db.execute(
        select(FindingSLA).where(FindingSLA.scan_id == scan_id).order_by(FindingSLA.due_at, FindingSLA.id)
    )
    return list(result.scalars())


async def build_security_debt_dashboard(
    db: AsyncSession,
    scan: Scan,
    *,
    governance: ExceptionAwareCompliance | None = None,
    at: datetime | None = None,
    preview_document: SecuritySLADocument | None = None,
) -> SecurityDebtDashboard:
    moment = _now(at)
    context = None
    from app.services.project_context import load_context_snapshot

    context = await load_context_snapshot(db, scan.id)
    if preview_document is not None:
        assigned = await ensure_security_sla(db, scan)
        snapshot = SecuritySLASnapshot(
            profile_id="preview",
            root_scan_id=assigned.root_scan_id,
            version=0,
            source="preview",
            sla_sha256=sla_sha256(preview_document),
            document=preview_document,
        )
        rows: list[FindingSLA] = []
        first_seen = _utc(scan.created_at or moment)
        for finding in scan.findings:
            assignment = compute_sla_assignment(finding, snapshot, context)
            if assignment is None:
                continue
            due_at = first_seen + timedelta(hours=assignment.due_hours)
            rows.append(
                FindingSLA(
                    id=f"preview-{finding.id}",
                    finding_id=finding.id,
                    scan_id=scan.id,
                    root_scan_id=snapshot.root_scan_id,
                    profile_id="preview",
                    fingerprint=finding_fingerprint(finding),
                    asset_id=assignment.asset_id,
                    effective_severity=_effective_severity(finding) or "high",
                    assigned_team=assignment.assigned_team,
                    risk_owner=assignment.risk_owner,
                    escalation_contact=assignment.escalation_contact,
                    assignment_source="preview",
                    matched_override_id=assignment.matched_override_id,
                    started_at=first_seen,
                    at_risk_at=max(first_seen, due_at - timedelta(hours=preview_document.at_risk_window_hours)),
                    due_at=due_at,
                )
            )
        profile_versions = {"preview": (0, snapshot.sla_sha256)}
    else:
        await persist_finding_slas(db, scan, context)
        rows = await _sla_rows(db, scan.id)
        profile_ids = {item.profile_id for item in rows}
        profile_versions: dict[str, tuple[int, str]] = {}
        for profile_id in profile_ids:
            profile = await _profile(db, profile_id)
            profile_versions[profile_id] = (profile.version, profile.sla_sha256)
        snapshot = await load_sla_snapshot(db, scan.id)
        assert snapshot is not None

    finding_by_id = {item.id: item for item in scan.findings}
    governance_by_id = {item.finding_id: item for item in governance.results} if governance else {}
    responses: list[FindingSLAResponse] = []
    team_counts: dict[str, dict[str, int]] = {}
    for row in rows:
        finding = finding_by_id.get(row.finding_id)
        if finding is None:
            continue
        started = _utc(row.started_at)
        due = _utc(row.due_at)
        at_risk_at = _utc(row.at_risk_at)
        if moment >= due:
            state = "overdue"
        elif moment >= at_risk_at:
            state = "at_risk"
        else:
            state = "on_track"
        gov = governance_by_id.get(finding.id)
        accepted = bool(gov and gov.disposition == "accepted_risk")
        exception_expiry = _utc(gov.exception_expires_at) if gov and gov.exception_expires_at else None
        version, digest = profile_versions[row.profile_id]
        response = FindingSLAResponse(
            finding_id=finding.id,
            fingerprint=row.fingerprint,
            rule_id=finding.rule_id,
            title=finding.title,
            file_path=finding.file_path,
            line=finding.line,
            severity=row.effective_severity,
            asset_id=row.asset_id,
            assigned_team=row.assigned_team,
            risk_owner=row.risk_owner,
            escalation_contact=row.escalation_contact,
            assignment_source=row.assignment_source,
            matched_override_id=row.matched_override_id,
            profile_version=version,
            profile_sha256=digest,
            started_at=started,
            at_risk_at=at_risk_at,
            due_at=due,
            age_hours=round(max(0.0, (moment - started).total_seconds() / 3600), 2),
            remaining_hours=round((due - moment).total_seconds() / 3600, 2),
            state=state,
            accepted_risk=accepted,
            exception_id=gov.exception_id if gov else None,
            exception_expires_at=exception_expiry,
            exception_outlives_sla=bool(exception_expiry and exception_expiry > due),
            sla_blocker=state == "overdue",
        )
        responses.append(response)
        counts = team_counts.setdefault(
            row.assigned_team,
            {"total": 0, "on_track": 0, "at_risk": 0, "overdue": 0, "accepted_risk": 0},
        )
        counts["total"] += 1
        counts[state] += 1
        counts["accepted_risk"] += int(accepted)

    responses.sort(
        key=lambda item: (
            {"overdue": 0, "at_risk": 1, "on_track": 2}[item.state],
            -SEVERITY_ORDER.get(item.severity, 0),
            item.due_at,
            item.file_path,
        )
    )
    overdue = sum(item.state == "overdue" for item in responses)
    at_risk = sum(item.state == "at_risk" for item in responses)
    accepted = sum(item.accepted_risk for item in responses)
    governance_blocked = bool(governance and not governance.release_permitted)
    if overdue or governance_blocked:
        state = "blocked"
    elif accepted:
        state = "accepted_risk"
    elif at_risk:
        state = "at_risk"
    else:
        state = "passed"
    teams = [TeamDebtSummary(team=team, **counts) for team, counts in sorted(team_counts.items())]
    return SecurityDebtDashboard(
        scan_id=scan.id,
        generated_at=moment,
        state=state,
        release_permitted=not overdue and not governance_blocked,
        profile_version=snapshot.version,
        profile_sha256=snapshot.sla_sha256,
        profile_name=snapshot.document.profile_name,
        summary=SecurityDebtSummary(
            total=len(responses),
            on_track=sum(item.state == "on_track" for item in responses),
            at_risk=at_risk,
            overdue=overdue,
            accepted_risk=accepted,
            unassigned=sum("unassigned" in item.assigned_team.casefold() for item in responses),
            due_within_7_days=sum(0 < item.remaining_hours <= 168 for item in responses),
            oldest_age_hours=max((item.age_hours for item in responses), default=0.0),
            sla_blockers=overdue,
        ),
        teams=teams,
        findings=responses,
    )


def compare_security_debt(
    baseline: SecurityDebtDashboard,
    current: SecurityDebtDashboard,
) -> SecurityDebtComparison:
    before = {item.fingerprint: item for item in baseline.findings}
    after = {item.fingerprint: item for item in current.findings}
    introduced_keys = sorted(after.keys() - before.keys())
    resolved_keys = sorted(before.keys() - after.keys())
    persistent_keys = sorted(before.keys() & after.keys())
    return SecurityDebtComparison(
        baseline_scan_id=baseline.scan_id,
        current_scan_id=current.scan_id,
        summary=SecurityDebtComparisonSummary(
            baseline_total=len(before),
            current_total=len(after),
            introduced=len(introduced_keys),
            resolved=len(resolved_keys),
            persistent=len(persistent_keys),
            newly_overdue=sum(
                before[key].state != "overdue" and after[key].state == "overdue"
                for key in persistent_keys
            ),
            recovered_from_overdue=sum(
                before[key].state == "overdue" and after[key].state != "overdue"
                for key in persistent_keys
            ),
            owner_changed=sum(before[key].assigned_team != after[key].assigned_team for key in persistent_keys),
            release_state_changed=baseline.release_permitted != current.release_permitted,
        ),
        introduced=[after[key] for key in introduced_keys],
        resolved=[before[key] for key in resolved_keys],
        persistent=[after[key] for key in persistent_keys],
        baseline=baseline,
        current=current,
    )


async def exception_deadline_for_target(
    db: AsyncSession,
    scan: Scan,
    *,
    target_type: str,
    target_value: str,
) -> datetime | None:
    context = None
    from app.services.project_context import load_context_snapshot

    context = await load_context_snapshot(db, scan.id)
    await persist_finding_slas(db, scan, context)
    rows = await _sla_rows(db, scan.id)
    findings = {item.id: item for item in scan.findings}
    matches: list[FindingSLA] = []
    for row in rows:
        finding = findings.get(row.finding_id)
        if finding is None:
            continue
        matched = (
            (target_type == "finding" and finding.id == target_value)
            or (target_type == "rule" and finding.rule_id == target_value)
            or (target_type == "asset" and row.asset_id == target_value)
        )
        if matched:
            matches.append(row)
    return min((_utc(item.due_at) for item in matches), default=None)


async def exception_deadline_for_scope(
    db: AsyncSession,
    scan: Scan,
    *,
    scope_type: str,
    scope_value: str,
) -> datetime | None:
    context = None
    from app.services.project_context import load_context_snapshot

    context = await load_context_snapshot(db, scan.id)
    await persist_finding_slas(db, scan, context)
    rows = await _sla_rows(db, scan.id)
    findings = {item.id: item for item in scan.findings}
    matches: list[FindingSLA] = []
    for row in rows:
        finding = findings.get(row.finding_id)
        if finding is None:
            continue
        matched = (
            (scope_type == "fingerprint" and row.fingerprint == scope_value)
            or (scope_type == "rule" and finding.rule_id == scope_value)
            or (scope_type == "asset" and row.asset_id == scope_value)
        )
        if matched:
            matches.append(row)
    return min((_utc(item.due_at) for item in matches), default=None)
