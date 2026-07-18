from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.comparison import build_scan_comparison
from app.services.demo_fixture import create_judge_demo_archive
from app.services.demo_reviewer import DemoReviewer
from app.services.lineage import build_lineage_response, ensure_root_lineage, link_rescan
from app.services.project_context import (
    assign_latest_project_context,
    demo_project_context,
    ensure_project_context,
    load_context_snapshot,
)
from app.services.rescan import prepare_rescan
from app.services.scanner import process_scan
from app.services.security_policy import (
    assign_latest_security_policy,
    demo_security_policy,
    ensure_security_policy,
    evaluate_security_policy,
    load_policy_snapshot,
)
from app.services.security_sla import (
    assign_latest_security_sla,
    build_security_debt_dashboard,
    demo_security_sla,
    ensure_security_sla,
    load_sla_snapshot,
)


async def test_golden_rescan_uses_real_pipeline_and_produces_a_clean_delta(tmp_path: Path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path}/baseline.db"
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    settings = Settings(database_url=database_url, data_dir=tmp_path / "data", openai_api_key=None)
    baseline_workspace = settings.scans_dir / "baseline"
    baseline_workspace.mkdir(parents=True)
    create_judge_demo_archive(baseline_workspace / "source.zip")
    baseline = Scan(
        id="baseline",
        status="queued",
        source_type="zip",
        original_filename="sentinel-judge-demo-replay.zip",
        workspace_path=str(baseline_workspace),
    )
    async with factory() as session:
        session.add(baseline)
        await session.flush()
        await ensure_root_lineage(session, baseline)
        await ensure_project_context(session, baseline, demo_project_context(), source="built_in")
        await ensure_security_policy(session, baseline, demo_security_policy(), source="built_in")
        await ensure_security_sla(session, baseline, demo_security_sla(), source="built_in")
        await session.commit()

    reviewer = DemoReviewer(settings)
    await process_scan("baseline", reviewer=reviewer, session_factory=factory, pipeline_settings=settings)
    current = prepare_rescan(baseline, "current", settings)
    async with factory() as session:
        session.add(current)
        await session.flush()
        await link_rescan(session, baseline, current)
        await assign_latest_project_context(session, baseline, current)
        await assign_latest_security_policy(session, baseline, current)
        await assign_latest_security_sla(session, baseline, current)
        await session.commit()
    await process_scan("current", reviewer=reviewer, session_factory=factory, pipeline_settings=settings)

    async with factory() as session:
        scans = {}
        for scan_id in ("baseline", "current"):
            result = await session.execute(
                select(Scan)
                .options(
                    selectinload(Scan.findings).selectinload(Finding.verification),
                    selectinload(Scan.findings).selectinload(Finding.decision),
                    selectinload(Scan.findings).selectinload(Finding.risk_intelligence),
                )
                .where(Scan.id == scan_id)
            )
            scans[scan_id] = result.scalar_one()
        comparison = build_scan_comparison(scans["baseline"], scans["current"])
        lineage = await build_lineage_response(session, scans["current"])
        current_context = await load_context_snapshot(session, "current")
        current_policy = await load_policy_snapshot(session, "current")
        assert current_policy is not None
        policy_compliance = evaluate_security_policy(
            "current", list(scans["current"].findings), current_policy, current_context
        )
        current_sla = await load_sla_snapshot(session, "current")
        sla_dashboard = await build_security_debt_dashboard(session, scans["current"])

    assert scans["baseline"].status == "completed"
    assert scans["current"].status == "completed"
    assert sum(finding.risk_intelligence is not None for finding in scans["current"].findings) == 2
    assert current_context is not None
    assert current_context.source == "built_in"
    assert current_context.version == 1
    assert current_policy.source == "built_in"
    assert current_sla is not None
    assert current_sla.source == "built_in"
    assert current_sla.version == 1
    assert sla_dashboard.summary.total == 2
    assert {item.assigned_team for item in sla_dashboard.findings} == {
        "Customer Platform",
        "Inventory Services",
    }
    assert all(item.assignment_source == "lineage_inherited" for item in sla_dashboard.findings)
    assert current_policy.version == 1
    assert policy_compliance.state == "blocked"
    assert policy_compliance.summary.blocking_findings == 2
    assert {
        finding.risk_intelligence.context_asset_id
        for finding in scans["current"].findings
        if finding.risk_intelligence is not None
    } == {"customer-data-api", "inventory-query-service"}
    assert comparison.summary.persistent == 3
    assert comparison.summary.introduced == 0
    assert comparison.summary.resolved == 0
    assert comparison.summary.changed == 0
    assert comparison.delta_gate.passed is True
    assert comparison.current_gate.passed is False
    assert lineage.root_scan_id == "baseline"
    assert lineage.parent_scan_id == "baseline"
    assert [(node.scan_id, node.generation) for node in lineage.nodes] == [("baseline", 0), ("current", 1)]
    await engine.dispose()
