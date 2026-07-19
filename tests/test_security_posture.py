from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.lineage import ensure_root_lineage, link_rescan
from app.services.project_context import assign_latest_project_context, ensure_project_context
from app.services.security_policy import assign_latest_security_policy, ensure_security_policy
from app.services.security_posture import build_security_posture_trend
from app.services.security_sla import assign_latest_security_sla, ensure_security_sla


def finding(finding_id: str, *, line: int = 8, snippet: str = "cursor.execute(query)") -> Finding:
    return Finding(
        id=finding_id,
        rule_id="PY_SQL_INTERPOLATION",
        title="SQL injection",
        file_path="app/query.py",
        line=line,
        end_line=line,
        language="python",
        snippet=snippet,
        static_rationale="Request data reaches SQL.",
        static_confidence=0.98,
        llm_status="completed",
        confirmed=True,
        severity="high",
        confidence=0.98,
        patch_valid=False,
    )


async def add_rescan_assignments(session: AsyncSession, baseline: Scan, current: Scan) -> None:
    await link_rescan(session, baseline, current)
    await assign_latest_project_context(session, baseline, current)
    await assign_latest_security_policy(session, baseline, current)
    await assign_latest_security_sla(session, baseline, current)


async def test_posture_tracks_resolution_sla_and_exact_recurrence(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/posture.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    started = datetime(2026, 7, 1, 8, 0, tzinfo=UTC)
    baseline = Scan(
        id="baseline",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "baseline"),
        candidate_count=1,
        finding_count=1,
        created_at=started,
        completed_at=started,
    )
    baseline.findings.append(finding("finding-baseline"))
    resolved = Scan(
        id="resolved",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "resolved"),
        candidate_count=0,
        finding_count=0,
        created_at=started + timedelta(hours=10),
        completed_at=started + timedelta(hours=10),
    )
    reopened = Scan(
        id="reopened",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "reopened"),
        candidate_count=1,
        finding_count=1,
        created_at=started + timedelta(hours=20),
        completed_at=started + timedelta(hours=20),
    )
    reopened.findings.append(finding("finding-reopened", line=88))

    async with factory() as session:
        session.add(baseline)
        await session.flush()
        await ensure_root_lineage(session, baseline)
        await ensure_project_context(session, baseline)
        await ensure_security_policy(session, baseline)
        await ensure_security_sla(session, baseline)

        session.add(resolved)
        await session.flush()
        await add_rescan_assignments(session, baseline, resolved)

        session.add(reopened)
        await session.flush()
        await add_rescan_assignments(session, resolved, reopened)
        await session.commit()

        trend = await build_security_posture_trend(session, reopened, generated_at=started + timedelta(hours=21))

    assert [point.scan_id for point in trend.points] == ["baseline", "resolved", "reopened"]
    assert trend.points[0].delta.introduced == 1
    assert trend.points[1].delta.resolved == 1
    assert trend.points[1].direction == "improving"
    assert trend.points[2].delta.reopened == 1
    assert trend.points[2].direction == "worsening"
    assert trend.remediation.resolution_events == 1
    assert trend.remediation.reopened_events == 1
    assert trend.remediation.recurrence_rate == 100.0
    assert trend.remediation.mean_resolution_hours == 10.0
    assert trend.remediation.resolved_within_sla == 1
    assert trend.remediation.sla_attainment_rate == 100.0
    assert trend.remediation.currently_active_fingerprints == 1
    assert trend.remediation.recurrences[0].current_active is True
    assert trend.summary.total_resolved == 1
    assert trend.summary.total_reopened == 1
    await engine.dispose()


async def test_changed_evidence_is_one_continuous_episode_not_a_resolution(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/changed.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    started = datetime(2026, 7, 2, 8, 0, tzinfo=UTC)
    baseline = Scan(
        id="base",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "base"),
        candidate_count=1,
        finding_count=1,
        created_at=started,
        completed_at=started,
    )
    baseline.findings.append(finding("old", line=8, snippet="cursor.execute(query)"))
    changed = Scan(
        id="changed",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "changed"),
        candidate_count=1,
        finding_count=1,
        created_at=started + timedelta(hours=4),
        completed_at=started + timedelta(hours=4),
    )
    changed.findings.append(finding("new", line=9, snippet="cursor.execute(unsafe_query)"))

    async with factory() as session:
        session.add(baseline)
        await session.flush()
        await ensure_root_lineage(session, baseline)
        await ensure_project_context(session, baseline)
        await ensure_security_policy(session, baseline)
        await ensure_security_sla(session, baseline)
        session.add(changed)
        await session.flush()
        await add_rescan_assignments(session, baseline, changed)
        await session.commit()
        trend = await build_security_posture_trend(session, changed)

    assert trend.points[1].delta.changed == 1
    assert trend.remediation.resolution_events == 0
    assert trend.remediation.currently_active_fingerprints == 1
    await engine.dispose()
