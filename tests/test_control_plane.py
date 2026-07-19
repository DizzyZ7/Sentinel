from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.control_plane import (
    PortfolioAlert,
    PortfolioAuditEvent,
    PortfolioSnapshot,
)
from app.models.scan import Scan
from app.schemas.control_plane import (
    AlertAcknowledgeRequest,
    AlertResolveRequest,
    PortfolioControlDocument,
    SnapshotCaptureRequest,
)
from app.schemas.portfolio import PortfolioCreate, PortfolioGovernanceDocument, PortfolioMemberInput
from app.services.control_plane import (
    acknowledge_alert,
    build_control_plane_evidence,
    build_schedule_status,
    capture_snapshot,
    control_status,
    create_control_profile_version,
    list_alerts,
    resolve_alert,
    verify_control_plane_chains,
)
from app.services.lineage import ensure_root_lineage
from app.services.portfolio import create_portfolio, upsert_portfolio_member
from app.services.project_context import ensure_project_context
from app.services.security_objective import ensure_security_objective
from app.services.security_policy import ensure_security_policy
from app.services.security_sla import ensure_security_sla


async def prepare_root(session: AsyncSession, scan: Scan) -> None:
    session.add(scan)
    await session.flush()
    await ensure_root_lineage(session, scan)
    await ensure_project_context(session, scan)
    await ensure_security_policy(session, scan)
    await ensure_security_sla(session, scan)
    await ensure_security_objective(session, scan)


async def test_snapshots_are_idempotent_chained_and_capture_recovery(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/control.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    t0 = datetime(2026, 7, 19, 9, 0, tzinfo=UTC)
    root = Scan(
        id="control-root",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "root"),
        created_at=t0,
        completed_at=t0,
    )
    async with factory() as session:
        await prepare_root(session, root)
        portfolio = await create_portfolio(
            session,
            PortfolioCreate(
                name="Control plane",
                governance=PortfolioGovernanceDocument(max_scan_age_days=365),
            ),
        )
        first = await capture_snapshot(
            session,
            portfolio,
            SnapshotCaptureRequest(actor="ci", source="scheduled", idempotency_key="run-1"),
            captured_at=t0,
        )
        duplicate = await capture_snapshot(
            session,
            portfolio,
            SnapshotCaptureRequest(actor="ci", source="scheduled", idempotency_key="run-1"),
            captured_at=t0 + timedelta(minutes=5),
        )
        await upsert_portfolio_member(
            session,
            portfolio,
            PortfolioMemberInput(root_scan_id=root.id, display_name="Core API", criticality="critical"),
        )
        second = await capture_snapshot(
            session,
            portfolio,
            SnapshotCaptureRequest(actor="ci", source="scheduled", idempotency_key="run-2"),
            captured_at=t0 + timedelta(days=1),
        )
        await session.commit()
        events = list(
            (
                await session.execute(
                    PortfolioAuditEvent.__table__.select()
                    .where(PortfolioAuditEvent.portfolio_id == portfolio.id)
                    .order_by(PortfolioAuditEvent.sequence)
                )
            ).mappings()
        )
        alerts = await list_alerts(session, portfolio.id)
    assert first.created is True
    assert first.snapshot.state == "insufficient_evidence"
    assert duplicate.created is False
    assert duplicate.snapshot.snapshot_id == first.snapshot.snapshot_id
    assert duplicate.snapshot.snapshot_sha256 == first.snapshot.snapshot_sha256
    assert second.snapshot.sequence == 2
    assert second.snapshot.previous_snapshot_sha256 == first.snapshot.snapshot_sha256
    assert second.snapshot.transition.direction == "improved"
    assert any(item.rule_key == "portfolio_insufficient_evidence" and item.status == "resolved" for item in alerts)
    for index, event in enumerate(events):
        if index == 0:
            assert event["previous_event_sha256"] is None
        else:
            assert event["previous_event_sha256"] == events[index - 1]["event_sha256"]
    await engine.dispose()


async def test_alert_lifecycle_acknowledge_resolve_and_reopen(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/alerts.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    t0 = datetime(2026, 7, 19, 9, 0, tzinfo=UTC)
    async with factory() as session:
        portfolio = await create_portfolio(session, PortfolioCreate(name="Empty portfolio"))
        first = await capture_snapshot(
            session,
            portfolio,
            SnapshotCaptureRequest(actor="ops", idempotency_key="first"),
            captured_at=t0,
        )
        alerts = await list_alerts(session, portfolio.id, status="open")
        target = next(item for item in alerts if item.rule_key == "portfolio_insufficient_evidence")
        acknowledged = await acknowledge_alert(
            session,
            portfolio.id,
            target.alert_id,
            AlertAcknowledgeRequest(actor="alice"),
            occurred_at=t0 + timedelta(minutes=1),
        )
        acknowledged_status = acknowledged.status
        resolved = await resolve_alert(
            session,
            portfolio.id,
            target.alert_id,
            AlertResolveRequest(actor="alice", reason="Accepted for test"),
            occurred_at=t0 + timedelta(minutes=2),
        )
        resolved_status = resolved.status
        second = await capture_snapshot(
            session,
            portfolio,
            SnapshotCaptureRequest(actor="ops", idempotency_key="second"),
            captured_at=t0 + timedelta(hours=1),
        )
        await session.commit()
        reopened = await session.get(PortfolioAlert, target.alert_id)
    assert first.alerts_opened > 0
    assert acknowledged_status == "acknowledged"
    assert resolved_status == "resolved"
    assert second.alerts_reopened >= 1
    assert reopened is not None
    assert reopened.status == "open"
    assert reopened.occurrence_count == 2
    assert reopened.acknowledged_by is None
    await engine.dispose()


async def test_control_profiles_schedule_and_evidence_are_reproducible(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/evidence.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    t0 = datetime(2026, 7, 19, 9, 0, tzinfo=UTC)
    async with factory() as session:
        portfolio = await create_portfolio(session, PortfolioCreate(name="Evidence"))
        await capture_snapshot(
            session,
            portfolio,
            SnapshotCaptureRequest(actor="ci", idempotency_key="baseline"),
            captured_at=t0,
        )
        due = await build_schedule_status(session, portfolio, generated_at=t0 + timedelta(hours=25))
        overdue = await build_schedule_status(session, portfolio, generated_at=t0 + timedelta(hours=49))
        await create_control_profile_version(
            session,
            portfolio,
            PortfolioControlDocument(snapshot_interval_hours=12, route_labels=["soc", "engineering"]),
            actor="security-lead",
            occurred_at=t0 + timedelta(hours=50),
        )
        profile_status = await control_status(session, portfolio)
        first = await build_control_plane_evidence(session, portfolio, generated_at=t0 + timedelta(hours=51))
        second = await build_control_plane_evidence(session, portfolio, generated_at=t0 + timedelta(hours=51))
        await session.commit()
    assert due.schedule_state == "due"
    assert overdue.schedule_state == "overdue"
    assert profile_status.latest_profile.version == 2
    assert profile_status.latest_profile.document.route_labels == ["soc", "engineering"]
    assert first.integrity.payload_sha256 == second.integrity.payload_sha256
    assert first.integrity.section_sha256["audit_events"] == second.integrity.section_sha256["audit_events"]
    assert first.versions["control_plane_engine"] == "sentinel-control-plane-v1"
    assert first.audit_events[-1].previous_event_sha256 == first.audit_events[-2].event_sha256
    await engine.dispose()


async def test_chain_verification_detects_snapshot_and_audit_tampering(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/tamper.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    t0 = datetime(2026, 7, 19, 9, 0, tzinfo=UTC)
    async with factory() as session:
        portfolio = await create_portfolio(session, PortfolioCreate(name="Tamper detection"))
        captured = await capture_snapshot(
            session,
            portfolio,
            SnapshotCaptureRequest(actor="ci", idempotency_key="tamper-baseline"),
            captured_at=t0,
        )
        valid = await verify_control_plane_chains(session, portfolio.id)
        snapshot = await session.get(PortfolioSnapshot, captured.snapshot.snapshot_id)
        assert snapshot is not None
        dashboard = dict(snapshot.dashboard)
        dashboard["schema_version"] = "tampered"
        snapshot.dashboard = dashboard
        event_result = await session.execute(
            PortfolioAuditEvent.__table__.select()
            .where(PortfolioAuditEvent.portfolio_id == portfolio.id)
            .order_by(PortfolioAuditEvent.sequence)
            .limit(1)
        )
        event_id = event_result.mappings().one()["id"]
        event = await session.get(PortfolioAuditEvent, event_id)
        assert event is not None
        event.payload = {"tampered": True}
        await session.flush()
        invalid = await verify_control_plane_chains(session, portfolio.id)
    assert valid.snapshot_chain_valid is True
    assert valid.audit_chain_valid is True
    assert invalid.snapshot_chain_valid is False
    assert invalid.audit_chain_valid is False
    assert any("dashboard SHA-256" in item for item in invalid.failures)
    assert any("event SHA-256" in item for item in invalid.failures)
    await engine.dispose()
