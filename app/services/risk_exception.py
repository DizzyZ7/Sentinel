from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.lineage import ScanLineage
from app.models.risk_exception import RiskException, RiskExceptionEvent
from app.models.scan import Scan
from app.schemas.risk_exception import (
    ExceptionAwareCompliance,
    ExceptionAwareFindingResult,
    ExceptionDebtComparison,
    ExceptionDebtComparisonSummary,
    ExceptionDebtItem,
    ExceptionGovernanceSummary,
    RiskExceptionCreate,
    RiskExceptionDecisionRequest,
    RiskExceptionEventResponse,
    RiskExceptionList,
    RiskExceptionRenewRequest,
    RiskExceptionResponse,
    RiskExceptionRevokeRequest,
)
from app.schemas.security_policy import SecurityPolicyCompliance
from app.services.comparison import finding_fingerprint
from app.services.policy import SEVERITY_RANK
from app.services.project_context import ProjectContextSnapshot
from app.services.risk_intelligence import build_risk_intelligence

EXCEPTION_ENGINE_VERSION = "sentinel-risk-exception-v1"
MAX_EXCEPTION_DURATION = timedelta(days=90)
MIN_EXCEPTION_DURATION = timedelta(hours=1)
EXPIRING_SOON = timedelta(days=7)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _now(value: datetime | None = None) -> datetime:
    return _utc(value or datetime.now(UTC))


async def _root_scan_id(db: AsyncSession, scan: Scan) -> str:
    lineage = await db.get(ScanLineage, scan.id)
    return lineage.root_scan_id if lineage else scan.id


def _event_metadata(event: RiskExceptionEvent) -> dict:
    if not event.event_metadata:
        return {}
    try:
        value = json.loads(event.event_metadata)
    except json.JSONDecodeError:
        return {"raw": event.event_metadata}
    return value if isinstance(value, dict) else {"value": value}


def effective_exception_status(item: RiskException, at: datetime | None = None) -> str:
    moment = _now(at)
    if item.status == "approved" and _utc(item.expires_at) <= moment:
        return "expired"
    return item.status


def exception_active_at(item: RiskException, at: datetime | None = None) -> bool:
    moment = _now(at)
    if item.decision_by is None or item.decided_at is None:
        return False
    if item.status == "rejected":
        return False
    if _utc(item.decided_at) > moment:
        return False
    if item.revoked_at is not None and _utc(item.revoked_at) <= moment:
        return False
    return _utc(item.expires_at) > moment


def _target_label(item: RiskException) -> str:
    labels = {
        "fingerprint": "Finding fingerprint",
        "rule": "Rule",
        "asset": "Asset",
    }
    return f"{labels.get(item.scope_type, item.scope_type)}: {item.scope_value}"


async def _events_by_exception(
    db: AsyncSession,
    exception_ids: list[str],
) -> dict[str, list[RiskExceptionEvent]]:
    if not exception_ids:
        return {}
    result = await db.execute(
        select(RiskExceptionEvent)
        .where(RiskExceptionEvent.exception_id.in_(exception_ids))
        .order_by(RiskExceptionEvent.created_at, RiskExceptionEvent.id)
    )
    grouped: dict[str, list[RiskExceptionEvent]] = {item: [] for item in exception_ids}
    for event in result.scalars():
        grouped.setdefault(event.exception_id, []).append(event)
    return grouped


def exception_response(
    item: RiskException,
    events: list[RiskExceptionEvent] | None = None,
    *,
    at: datetime | None = None,
) -> RiskExceptionResponse:
    status = effective_exception_status(item, at)
    return RiskExceptionResponse(
        id=item.id,
        root_scan_id=item.root_scan_id,
        created_scan_id=item.created_scan_id,
        scope_type=item.scope_type,
        scope_value=item.scope_value,
        target_label=_target_label(item),
        title=item.title,
        justification=item.justification,
        risk_owner=item.risk_owner,
        requested_by=item.requested_by,
        maximum_severity=item.maximum_severity,
        expires_at=_utc(item.expires_at),
        status=status,
        active=exception_active_at(item, at),
        decision_by=item.decision_by,
        decision_reason=item.decision_reason,
        decided_at=_utc(item.decided_at) if item.decided_at else None,
        revoked_by=item.revoked_by,
        revocation_reason=item.revocation_reason,
        revoked_at=_utc(item.revoked_at) if item.revoked_at else None,
        created_at=_utc(item.created_at) if item.created_at else None,
        events=[
            RiskExceptionEventResponse(
                id=event.id,
                event_type=event.event_type,
                actor=event.actor,
                reason=event.reason,
                metadata=_event_metadata(event),
                created_at=_utc(event.created_at) if event.created_at else None,
            )
            for event in (events or [])
        ],
    )


async def list_root_exceptions(db: AsyncSession, root_scan_id: str) -> list[RiskException]:
    result = await db.execute(
        select(RiskException)
        .where(RiskException.root_scan_id == root_scan_id)
        .order_by(RiskException.created_at.desc(), RiskException.id)
    )
    return list(result.scalars())


async def build_exception_list(
    db: AsyncSession,
    scan: Scan,
    *,
    at: datetime | None = None,
) -> RiskExceptionList:
    moment = _now(at)
    root_scan_id = await _root_scan_id(db, scan)
    items = await list_root_exceptions(db, root_scan_id)
    events = await _events_by_exception(db, [item.id for item in items])
    responses = [exception_response(item, events.get(item.id), at=moment) for item in items]
    return RiskExceptionList(
        scan_id=scan.id,
        root_scan_id=root_scan_id,
        generated_at=moment,
        pending=sum(item.status == "pending" for item in responses),
        active=sum(item.active for item in responses),
        expired=sum(item.status == "expired" for item in responses),
        rejected_or_revoked=sum(item.status in {"rejected", "revoked"} for item in responses),
        exceptions=responses,
    )


def _asset_id(finding: Finding, context: ProjectContextSnapshot | None) -> str | None:
    if not finding.confirmed or not finding.severity:
        return None
    risk = build_risk_intelligence(finding, context)
    return (risk.scoring_factors or {}).get("context", {}).get("asset_id")


def _resolve_scope(
    request: RiskExceptionCreate,
    findings: list[Finding],
    context: ProjectContextSnapshot | None,
) -> tuple[str, str]:
    if request.target_type == "finding":
        finding = next((item for item in findings if item.id == request.target_value), None)
        if finding is None:
            raise ValueError("Finding target does not exist in this scan")
        return "fingerprint", finding_fingerprint(finding)
    if request.target_type == "rule":
        if not any(item.rule_id == request.target_value for item in findings):
            raise ValueError("Rule target does not exist in this scan")
        return "rule", request.target_value
    if not any(_asset_id(item, context) == request.target_value for item in findings):
        raise ValueError("Asset target does not match a confirmed finding in this scan")
    return "asset", request.target_value


async def create_risk_exception(
    db: AsyncSession,
    scan: Scan,
    request: RiskExceptionCreate,
    context: ProjectContextSnapshot | None,
    *,
    created_at: datetime | None = None,
    latest_allowed_expiry: datetime | None = None,
) -> RiskException:
    moment = _now(created_at)
    expires_at = _utc(request.expires_at)
    duration = expires_at - moment
    if duration < MIN_EXCEPTION_DURATION:
        raise ValueError("Risk exceptions must remain valid for at least one hour")
    if duration > MAX_EXCEPTION_DURATION:
        raise ValueError("Risk exceptions cannot exceed 90 days")
    if latest_allowed_expiry is not None and expires_at > _utc(latest_allowed_expiry):
        raise ValueError(
            "Risk exception expiry cannot exceed the remediation SLA deadline "
            f"{_utc(latest_allowed_expiry).isoformat()}"
        )
    scope_type, scope_value = _resolve_scope(request, list(scan.findings), context)
    root_scan_id = await _root_scan_id(db, scan)
    item = RiskException(
        id=str(uuid.uuid4()),
        root_scan_id=root_scan_id,
        created_scan_id=scan.id,
        scope_type=scope_type,
        scope_value=scope_value,
        title=request.title,
        justification=request.justification,
        risk_owner=request.risk_owner,
        requested_by=request.requested_by,
        maximum_severity=request.maximum_severity,
        expires_at=expires_at,
        status="pending",
        created_at=moment,
    )
    db.add(item)
    await db.flush()
    db.add(
        RiskExceptionEvent(
            id=str(uuid.uuid4()),
            exception_id=item.id,
            event_type="requested",
            actor=request.requested_by,
            reason=request.justification,
            event_metadata=json.dumps(
                {
                    "scope_type": scope_type,
                    "scope_value": scope_value,
                    "risk_owner": request.risk_owner,
                    "maximum_severity": request.maximum_severity,
                    "expires_at": expires_at.isoformat(),
                },
                sort_keys=True,
            ),
            created_at=moment,
        )
    )
    await db.flush()
    return item


async def decide_risk_exception(
    db: AsyncSession,
    item: RiskException,
    request: RiskExceptionDecisionRequest,
    *,
    decided_at: datetime | None = None,
) -> RiskException:
    moment = _now(decided_at)
    if item.status != "pending":
        raise ValueError("Only pending exceptions can be decided")
    if _utc(item.expires_at) <= moment:
        raise ValueError("Expired exceptions cannot be approved or rejected")
    if request.actor.casefold() == item.requested_by.casefold():
        raise ValueError("The requester cannot approve or reject their own exception")
    item.status = request.decision
    item.decision_by = request.actor
    item.decision_reason = request.reason
    item.decided_at = moment
    db.add(
        RiskExceptionEvent(
            id=str(uuid.uuid4()),
            exception_id=item.id,
            event_type=request.decision,
            actor=request.actor,
            reason=request.reason,
            event_metadata=json.dumps({"previous_status": "pending"}, sort_keys=True),
            created_at=moment,
        )
    )
    await db.flush()
    return item


async def revoke_risk_exception(
    db: AsyncSession,
    item: RiskException,
    request: RiskExceptionRevokeRequest,
    *,
    revoked_at: datetime | None = None,
) -> RiskException:
    moment = _now(revoked_at)
    if not exception_active_at(item, moment):
        raise ValueError("Only active approved exceptions can be revoked")
    item.status = "revoked"
    item.revoked_by = request.actor
    item.revocation_reason = request.reason
    item.revoked_at = moment
    db.add(
        RiskExceptionEvent(
            id=str(uuid.uuid4()),
            exception_id=item.id,
            event_type="revoked",
            actor=request.actor,
            reason=request.reason,
            event_metadata=json.dumps({"previous_status": "approved"}, sort_keys=True),
            created_at=moment,
        )
    )
    await db.flush()
    return item



async def request_risk_exception_renewal(
    db: AsyncSession,
    item: RiskException,
    request: RiskExceptionRenewRequest,
    *,
    requested_at: datetime | None = None,
    latest_allowed_expiry: datetime | None = None,
) -> RiskException:
    moment = _now(requested_at)
    if not exception_active_at(item, moment):
        raise ValueError("Only active approved exceptions can be renewed")
    expires_at = _utc(request.expires_at)
    if expires_at <= _utc(item.expires_at):
        raise ValueError("A renewal must extend beyond the current exception expiry")
    duration = expires_at - moment
    if duration < MIN_EXCEPTION_DURATION:
        raise ValueError("Risk exception renewals must remain valid for at least one hour")
    if duration > MAX_EXCEPTION_DURATION:
        raise ValueError("Risk exception renewals cannot exceed 90 days from the request time")
    if latest_allowed_expiry is not None and expires_at > _utc(latest_allowed_expiry):
        raise ValueError(
            "Risk exception renewal cannot exceed the remediation SLA deadline "
            f"{_utc(latest_allowed_expiry).isoformat()}"
        )
    renewed = RiskException(
        id=str(uuid.uuid4()),
        root_scan_id=item.root_scan_id,
        created_scan_id=item.created_scan_id,
        scope_type=item.scope_type,
        scope_value=item.scope_value,
        title=f"Renewal: {item.title}"[:180],
        justification=request.reason,
        risk_owner=item.risk_owner,
        requested_by=request.actor,
        maximum_severity=item.maximum_severity,
        expires_at=expires_at,
        status="pending",
        created_at=moment,
    )
    db.add(renewed)
    await db.flush()
    db.add_all(
        [
            RiskExceptionEvent(
                id=str(uuid.uuid4()),
                exception_id=item.id,
                event_type="renewal_requested",
                actor=request.actor,
                reason=request.reason,
                event_metadata=json.dumps(
                    {"successor_exception_id": renewed.id, "requested_expiry": expires_at.isoformat()},
                    sort_keys=True,
                ),
                created_at=moment,
            ),
            RiskExceptionEvent(
                id=str(uuid.uuid4()),
                exception_id=renewed.id,
                event_type="requested",
                actor=request.actor,
                reason=request.reason,
                event_metadata=json.dumps(
                    {
                        "renews_exception_id": item.id,
                        "scope_type": item.scope_type,
                        "scope_value": item.scope_value,
                        "risk_owner": item.risk_owner,
                        "maximum_severity": item.maximum_severity,
                        "expires_at": expires_at.isoformat(),
                    },
                    sort_keys=True,
                ),
                created_at=moment,
            ),
        ]
    )
    await db.flush()
    return renewed

def _exception_matches(
    item: RiskException,
    finding: Finding,
    asset_id: str | None,
    *,
    at: datetime,
) -> bool:
    if not exception_active_at(item, at):
        return False
    if finding.severity not in SEVERITY_RANK:
        return False
    if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[item.maximum_severity]:
        return False
    if item.scope_type == "fingerprint":
        return item.scope_value == finding_fingerprint(finding)
    if item.scope_type == "rule":
        return item.scope_value == finding.rule_id
    return item.scope_type == "asset" and item.scope_value == asset_id


def _scope_priority(item: RiskException) -> tuple[int, datetime, str]:
    priority = {"fingerprint": 0, "asset": 1, "rule": 2}
    return priority.get(item.scope_type, 9), _utc(item.expires_at), item.id


def _non_waivable_reason(finding: Finding, blocker_reasons: list[str]) -> str | None:
    if finding.severity == "critical":
        return "Critical findings cannot be accepted through a temporary exception."
    if finding.llm_status in {"failed", "skipped", "pending"} and finding.static_confidence >= 0.9:
        return "Fail-closed unreviewed deterministic evidence cannot be excepted."
    if any("did not complete deep review" in reason for reason in blocker_reasons):
        return "Fail-closed unreviewed deterministic evidence cannot be excepted."
    return None


def evaluate_exception_aware_compliance(
    scan_id: str,
    findings: list[Finding],
    raw_policy_compliance: SecurityPolicyCompliance,
    exceptions: list[RiskException],
    *,
    at: datetime | None = None,
) -> ExceptionAwareCompliance:
    moment = _now(at)
    findings_by_id = {item.id: item for item in findings}
    results: list[ExceptionAwareFindingResult] = []
    accepted = blocked = 0
    active = [item for item in exceptions if exception_active_at(item, moment)]

    for policy_result in raw_policy_compliance.results:
        finding = findings_by_id.get(policy_result.finding_id)
        reasons = list(policy_result.blocker_reasons)
        if finding is None:
            continue
        if not reasons:
            results.append(
                ExceptionAwareFindingResult(
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    title=finding.title,
                    file_path=finding.file_path,
                    line=finding.line,
                    severity=finding.severity,
                    raw_blocker_reasons=[],
                    disposition="passed",
                )
            )
            continue

        non_waivable = _non_waivable_reason(finding, reasons)
        matches = sorted(
            (
                item
                for item in active
                if _exception_matches(item, finding, policy_result.context_asset_id, at=moment)
            ),
            key=_scope_priority,
        )
        selected = matches[0] if matches and non_waivable is None else None
        if selected is not None:
            accepted += 1
            disposition = "accepted_risk"
        else:
            blocked += 1
            disposition = "blocked"
        results.append(
            ExceptionAwareFindingResult(
                finding_id=finding.id,
                rule_id=finding.rule_id,
                title=finding.title,
                file_path=finding.file_path,
                line=finding.line,
                severity=finding.severity,
                raw_blocker_reasons=reasons,
                disposition=disposition,
                exception_id=selected.id if selected else None,
                exception_scope=(f"{selected.scope_type}:{selected.scope_value}" if selected else None),
                exception_expires_at=_utc(selected.expires_at) if selected else None,
                non_waivable_reason=non_waivable,
            )
        )

    if blocked:
        state = "blocked"
    elif accepted:
        state = "accepted_risk"
    else:
        state = "passed"
    pending_count = sum(effective_exception_status(item, moment) == "pending" for item in exceptions)
    expired_count = sum(effective_exception_status(item, moment) == "expired" for item in exceptions)
    expiring = sum(
        1
        for exception in exceptions
        if exception_active_at(exception, moment)
        and _utc(exception.expires_at) <= moment + EXPIRING_SOON
    )
    return ExceptionAwareCompliance(
        scan_id=scan_id,
        generated_at=moment,
        state=state,
        release_permitted=blocked == 0,
        raw_policy_compliance=raw_policy_compliance,
        summary=ExceptionGovernanceSummary(
            evaluated_findings=len(results),
            raw_blocking_findings=sum(bool(item.raw_blocker_reasons) for item in results),
            accepted_risk_findings=accepted,
            unwaived_blocking_findings=blocked,
            active_exceptions=len(active),
            pending_exceptions=pending_count,
            expired_exceptions=expired_count,
            expiring_within_7_days=expiring,
        ),
        results=sorted(
            results,
            key=lambda item: (
                {"blocked": 0, "accepted_risk": 1, "passed": 2}[item.disposition],
                -SEVERITY_RANK.get(item.severity or "", 0),
                item.file_path,
                item.line,
            ),
        ),
    )


def active_exception_debt(
    exceptions: list[RiskException],
    *,
    at: datetime,
) -> dict[str, RiskException]:
    active: dict[str, RiskException] = {}
    for item in sorted(exceptions, key=_scope_priority):
        if exception_active_at(item, at):
            active.setdefault(f"{item.scope_type}:{item.scope_value}", item)
    return active


def _debt_item(item: RiskException) -> ExceptionDebtItem:
    return ExceptionDebtItem(
        scope_key=f"{item.scope_type}:{item.scope_value}",
        scope_type=item.scope_type,
        scope_value=item.scope_value,
        exception_id=item.id,
        title=item.title,
        risk_owner=item.risk_owner,
        maximum_severity=item.maximum_severity,
        expires_at=_utc(item.expires_at),
    )


def compare_exception_debt(
    baseline_scan_id: str,
    current_scan_id: str,
    exceptions: list[RiskException],
    baseline: ExceptionAwareCompliance,
    current: ExceptionAwareCompliance,
    *,
    baseline_as_of: datetime,
    current_as_of: datetime,
) -> ExceptionDebtComparison:
    before = active_exception_debt(exceptions, at=_utc(baseline_as_of))
    after = active_exception_debt(exceptions, at=_utc(current_as_of))
    introduced_keys = sorted(after.keys() - before.keys())
    resolved_keys = sorted(before.keys() - after.keys())
    persistent_keys = sorted(before.keys() & after.keys())
    return ExceptionDebtComparison(
        baseline_scan_id=baseline_scan_id,
        current_scan_id=current_scan_id,
        baseline_as_of=_utc(baseline_as_of),
        current_as_of=_utc(current_as_of),
        summary=ExceptionDebtComparisonSummary(
            baseline_active_scopes=len(before),
            current_active_scopes=len(after),
            introduced=len(introduced_keys),
            resolved=len(resolved_keys),
            persistent=len(persistent_keys),
            baseline_accepted_findings=baseline.summary.accepted_risk_findings,
            current_accepted_findings=current.summary.accepted_risk_findings,
            governance_state_changed=baseline.state != current.state,
        ),
        introduced=[_debt_item(after[key]) for key in introduced_keys],
        resolved=[_debt_item(before[key]) for key in resolved_keys],
        persistent=[_debt_item(after[key]) for key in persistent_keys],
        baseline=baseline,
        current=current,
    )
