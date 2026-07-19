from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.security_objective import SecurityObjectiveDocument
from app.services.lineage import ensure_root_lineage, link_rescan
from app.services.project_context import assign_latest_project_context, ensure_project_context
from app.services.security_objective import (
    assign_latest_security_objective,
    build_security_objective_report,
    build_security_objective_status,
    create_security_objective_version,
    ensure_security_objective,
    load_objective_snapshot,
    objective_sha256,
)
from app.services.security_policy import assign_latest_security_policy, ensure_security_policy
from app.services.security_sla import assign_latest_security_sla, ensure_security_sla


def finding(finding_id: str, path: str) -> Finding:
    return Finding(
        id=finding_id,
        rule_id="PY_SQL_INTERPOLATION",
        title="SQL injection",
        file_path=path,
        line=8,
        end_line=8,
        language="python",
        snippet=f"cursor.execute({finding_id})",
        static_rationale="Request data reaches SQL.",
        static_confidence=0.98,
        llm_status="completed",
        confirmed=True,
        severity="high",
        confidence=0.98,
        patch_valid=False,
    )


async def add_assignments(session: AsyncSession, baseline: Scan, current: Scan) -> None:
    await link_rescan(session, baseline, current)
    await assign_latest_project_context(session, baseline, current)
    await assign_latest_security_policy(session, baseline, current)
    await assign_latest_security_sla(session, baseline, current)
    await assign_latest_security_objective(session, baseline, current)


async def test_objective_versions_are_immutable_and_rescan_uses_latest(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/objective.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
    root = Scan(
        id="root",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "root"),
        created_at=now,
        completed_at=now,
    )
    child = Scan(
        id="child",
        status="queued",
        source_type="zip",
        workspace_path=str(tmp_path / "child"),
        created_at=now + timedelta(days=1),
    )
    first_document = SecurityObjectiveDocument(target_date=now + timedelta(days=90))
    second_document = first_document.model_copy(update={"max_posture_score": 25.0})
    async with factory() as session:
        session.add(root)
        await session.flush()
        await ensure_root_lineage(session, root)
        first = await ensure_security_objective(session, root, first_document, source="declared")
        await create_security_objective_version(session, root, second_document)
        session.add(child)
        await session.flush()
        await link_rescan(session, root, child)
        assigned = await assign_latest_security_objective(session, root, child)
        await session.commit()
        root_snapshot = await load_objective_snapshot(session, root.id)
        child_snapshot = await load_objective_snapshot(session, child.id)
        status = await build_security_objective_status(session, root)
    assert first.version == 1
    assert assigned.version == 2
    assert root_snapshot and root_snapshot.version == 1
    assert child_snapshot and child_snapshot.version == 2
    assert status.assigned_profile.version == 1
    assert status.latest_profile.version == 2
    assert objective_sha256(first_document) != objective_sha256(second_document)
    await engine.dispose()


async def test_objective_report_forecasts_observed_burn_rate(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/forecast.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    started = datetime(2026, 7, 1, 8, 0, tzinfo=UTC)
    baseline = Scan(
        id="baseline",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "baseline"),
        candidate_count=4,
        finding_count=4,
        created_at=started,
        completed_at=started,
    )
    baseline.findings.extend(finding(f"f-{index}", f"app/query_{index}.py") for index in range(4))
    middle = Scan(
        id="middle",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "middle"),
        candidate_count=2,
        finding_count=2,
        created_at=started + timedelta(days=10),
        completed_at=started + timedelta(days=10),
    )
    middle.findings.extend(finding(f"m-{index}", f"app/query_{index}.py") for index in range(2))
    current = Scan(
        id="current",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "current"),
        candidate_count=1,
        finding_count=1,
        created_at=started + timedelta(days=20),
        completed_at=started + timedelta(days=20),
    )
    current.findings.append(finding("current-0", "app/query_0.py"))
    objective = SecurityObjectiveDocument(
        objective_name="Clear active debt",
        target_date=started + timedelta(days=30),
        max_posture_score=100,
        max_confirmed_findings=0,
        max_policy_blockers=100,
        max_overdue_findings=100,
        max_accepted_risk_findings=100,
        min_sla_attainment_rate=0,
        max_mean_resolution_hours=10000,
        max_recurrence_rate=100,
        require_release_gate_passed=False,
        require_policy_passed=False,
        require_governance_passed=False,
    )
    async with factory() as session:
        session.add(baseline)
        await session.flush()
        await ensure_root_lineage(session, baseline)
        await ensure_project_context(session, baseline)
        await ensure_security_policy(session, baseline)
        await ensure_security_sla(session, baseline)
        await ensure_security_objective(session, baseline, objective, source="declared")
        session.add(middle)
        await session.flush()
        await add_assignments(session, baseline, middle)
        session.add(current)
        await session.flush()
        await add_assignments(session, middle, current)
        await session.commit()
        report = await build_security_objective_report(session, current, generated_at=started + timedelta(days=20))
    assert report.evaluation.state == "at_risk"
    assert report.evaluation.summary.missed_checks == 1
    assert report.forecast.status == "on_track"
    assert report.forecast.confidence == "low"
    assert report.forecast.history_intervals == 2
    assert report.forecast.history_days == 20.0
    assert report.forecast.current_active_findings == 1
    assert report.forecast.resolution_rate_per_day == 0.15
    assert report.forecast.introduction_rate_per_day == 0.0
    assert report.forecast.projected_active_findings == 0.0
    await engine.dispose()


async def test_objective_forecast_fails_closed_on_insufficient_history(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/insufficient.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
    scan = Scan(
        id="single",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "single"),
        candidate_count=1,
        finding_count=1,
        created_at=now,
        completed_at=now,
    )
    scan.findings.append(finding("single-finding", "app/query.py"))
    objective = SecurityObjectiveDocument(
        target_date=now + timedelta(days=30),
        max_confirmed_findings=0,
        require_release_gate_passed=False,
        require_policy_passed=False,
        require_governance_passed=False,
    )
    async with factory() as session:
        session.add(scan)
        await session.flush()
        await ensure_root_lineage(session, scan)
        await ensure_project_context(session, scan)
        await ensure_security_policy(session, scan)
        await ensure_security_sla(session, scan)
        await ensure_security_objective(session, scan, objective, source="declared")
        await session.commit()
        report = await build_security_objective_report(session, scan)
    assert report.evaluation.state == "at_risk"
    assert report.forecast.status == "insufficient_history"
    assert report.forecast.confidence == "insufficient_history"
    assert report.forecast.projected_active_findings is None
    await engine.dispose()
