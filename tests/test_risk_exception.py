from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.risk_exception import (
    RiskExceptionCreate,
    RiskExceptionDecisionRequest,
    RiskExceptionRevokeRequest,
)
from app.services.lineage import ensure_root_lineage
from app.services.project_context import demo_project_context, ensure_project_context, load_context_snapshot
from app.services.risk_exception import (
    compare_exception_debt,
    create_risk_exception,
    decide_risk_exception,
    evaluate_exception_aware_compliance,
    exception_active_at,
    list_root_exceptions,
    revoke_risk_exception,
)
from app.services.security_policy import (
    demo_security_policy,
    ensure_security_policy,
    evaluate_security_policy,
    load_policy_snapshot,
)


def make_finding(*, finding_id: str = "finding-1", severity: str = "high") -> Finding:
    return Finding(
        id=finding_id,
        rule_id="PY_SQL_INTERPOLATION",
        title="SQL injection",
        file_path="confirmed_sql.py",
        line=8,
        end_line=8,
        language="python",
        snippet="cursor.execute(f'SELECT {user_id}')",
        static_rationale="User input reaches SQL.",
        static_confidence=0.98,
        llm_status="completed",
        confirmed=True,
        severity=severity,
        confidence=0.98,
        patch_valid=False,
    )


async def build_scan(tmp_path, *, severity: str = "high"):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/exceptions.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
    scan = Scan(
        id="scan-1",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(tmp_path / "scan"),
        created_at=now,
        completed_at=now,
    )
    scan.findings.append(make_finding(severity=severity))
    async with factory() as session:
        session.add(scan)
        await session.flush()
        await ensure_root_lineage(session, scan)
        await ensure_project_context(session, scan, demo_project_context(), source="built_in")
        await ensure_security_policy(session, scan, demo_security_policy(), source="built_in")
        await session.commit()
    return engine, factory, now


async def load_scan(session: AsyncSession) -> Scan:
    result = await session.execute(
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
            selectinload(Scan.findings).selectinload(Finding.risk_intelligence),
        )
        .where(Scan.id == "scan-1")
    )
    return result.scalar_one()


async def test_exception_lifecycle_accepts_then_restores_blocker_on_expiry(tmp_path) -> None:
    engine, factory, now = await build_scan(tmp_path)
    async with factory() as session:
        scan = await load_scan(session)
        context = await load_context_snapshot(session, scan.id)
        policy = await load_policy_snapshot(session, scan.id)
        assert policy is not None
        raw = evaluate_security_policy(scan.id, list(scan.findings), policy, context)
        request = RiskExceptionCreate(
            target_type="finding",
            target_value="finding-1",
            title="Legacy query migration",
            justification="The query is isolated behind a temporary compensating control while migration completes.",
            risk_owner="Payments owner",
            requested_by="developer@example.com",
            maximum_severity="high",
            expires_at=now + timedelta(days=30),
        )
        item = await create_risk_exception(session, scan, request, context, created_at=now)
        await decide_risk_exception(
            session,
            item,
            RiskExceptionDecisionRequest(
                decision="approved",
                actor="security@example.com",
                reason="Compensating controls are documented and the remediation date is acceptable.",
            ),
            decided_at=now + timedelta(minutes=5),
        )
        await session.commit()
        exceptions = await list_root_exceptions(session, scan.id)
        accepted = evaluate_exception_aware_compliance(
            scan.id,
            list(scan.findings),
            raw,
            exceptions,
            at=now + timedelta(days=1),
        )
        expired = evaluate_exception_aware_compliance(
            scan.id,
            list(scan.findings),
            raw,
            exceptions,
            at=now + timedelta(days=31),
        )
    assert accepted.state == "accepted_risk"
    assert accepted.release_permitted is True
    assert accepted.summary.accepted_risk_findings == 1
    assert expired.state == "blocked"
    assert expired.summary.expired_exceptions == 1
    await engine.dispose()


async def test_requester_cannot_self_approve_and_active_exception_can_be_revoked(tmp_path) -> None:
    engine, factory, now = await build_scan(tmp_path)
    async with factory() as session:
        scan = await load_scan(session)
        context = await load_context_snapshot(session, scan.id)
        item = await create_risk_exception(
            session,
            scan,
            RiskExceptionCreate(
                target_type="rule",
                target_value="PY_SQL_INTERPOLATION",
                title="Rule migration window",
                justification="The affected rule is covered by monitoring until the migration is completed.",
                risk_owner="Security owner",
                requested_by="owner@example.com",
                expires_at=now + timedelta(days=10),
            ),
            context,
            created_at=now,
        )
        with pytest.raises(ValueError, match="cannot approve"):
            await decide_risk_exception(
                session,
                item,
                RiskExceptionDecisionRequest(
                    decision="approved",
                    actor="owner@example.com",
                    reason="I approve my own request for testing purposes.",
                ),
                decided_at=now + timedelta(minutes=1),
            )
        await decide_risk_exception(
            session,
            item,
            RiskExceptionDecisionRequest(
                decision="approved",
                actor="security@example.com",
                reason="Independent approval after review of compensating controls.",
            ),
            decided_at=now + timedelta(minutes=2),
        )
        assert exception_active_at(item, now + timedelta(hours=1))
        await revoke_risk_exception(
            session,
            item,
            RiskExceptionRevokeRequest(
                actor="security@example.com",
                reason="The compensating control is no longer operating as documented.",
            ),
            revoked_at=now + timedelta(hours=2),
        )
        assert exception_active_at(item, now + timedelta(hours=1))
        assert not exception_active_at(item, now + timedelta(hours=3))
    await engine.dispose()


async def test_critical_and_unreviewed_findings_are_non_waivable(tmp_path) -> None:
    engine, factory, now = await build_scan(tmp_path, severity="critical")
    async with factory() as session:
        scan = await load_scan(session)
        context = await load_context_snapshot(session, scan.id)
        policy = await load_policy_snapshot(session, scan.id)
        assert policy is not None
        raw = evaluate_security_policy(scan.id, list(scan.findings), policy, context)
        item = await create_risk_exception(
            session,
            scan,
            RiskExceptionCreate(
                target_type="rule",
                target_value="PY_SQL_INTERPOLATION",
                title="Attempted critical exception",
                justification="A temporary exception is requested, but critical exposure must remain blocked.",
                risk_owner="Risk owner",
                requested_by="developer@example.com",
                maximum_severity="high",
                expires_at=now + timedelta(days=5),
            ),
            context,
            created_at=now,
        )
        await decide_risk_exception(
            session,
            item,
            RiskExceptionDecisionRequest(
                decision="approved",
                actor="security@example.com",
                reason="Approval exists only to prove that critical findings remain non-waivable.",
            ),
            decided_at=now + timedelta(minutes=1),
        )
        governance = evaluate_exception_aware_compliance(
            scan.id,
            list(scan.findings),
            raw,
            [item],
            at=now + timedelta(hours=1),
        )
    assert governance.state == "blocked"
    assert governance.results[0].non_waivable_reason
    await engine.dispose()


async def test_exception_debt_comparison_uses_scan_time_snapshots(tmp_path) -> None:
    engine, factory, now = await build_scan(tmp_path)
    async with factory() as session:
        scan = await load_scan(session)
        context = await load_context_snapshot(session, scan.id)
        policy = await load_policy_snapshot(session, scan.id)
        assert policy is not None
        raw = evaluate_security_policy(scan.id, list(scan.findings), policy, context)
        item = await create_risk_exception(
            session,
            scan,
            RiskExceptionCreate(
                target_type="rule",
                target_value="PY_SQL_INTERPOLATION",
                title="Later exception",
                justification="This exception is approved after the baseline snapshot and before the current snapshot.",
                risk_owner="Risk owner",
                requested_by="developer@example.com",
                expires_at=now + timedelta(days=20),
            ),
            context,
            created_at=now + timedelta(days=1),
        )
        await decide_risk_exception(
            session,
            item,
            RiskExceptionDecisionRequest(
                decision="approved",
                actor="security@example.com",
                reason="Approved after baseline and before current generation for debt comparison.",
            ),
            decided_at=now + timedelta(days=2),
        )
        baseline = evaluate_exception_aware_compliance(
            "baseline", list(scan.findings), raw, [item], at=now
        )
        current = evaluate_exception_aware_compliance(
            "current", list(scan.findings), raw, [item], at=now + timedelta(days=3)
        )
        comparison = compare_exception_debt(
            "baseline",
            "current",
            [item],
            baseline,
            current,
            baseline_as_of=now,
            current_as_of=now + timedelta(days=3),
        )
    assert comparison.summary.introduced == 1
    assert comparison.summary.current_active_scopes == 1
    assert comparison.summary.current_accepted_findings == 1
    await engine.dispose()
