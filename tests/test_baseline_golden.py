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
from app.services.rescan import prepare_rescan
from app.services.scanner import process_scan


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
        await session.commit()

    reviewer = DemoReviewer(settings)
    await process_scan("baseline", reviewer=reviewer, session_factory=factory, pipeline_settings=settings)
    current = prepare_rescan(baseline, "current", settings)
    async with factory() as session:
        session.add(current)
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
                )
                .where(Scan.id == scan_id)
            )
            scans[scan_id] = result.scalar_one()
        comparison = build_scan_comparison(scans["baseline"], scans["current"])

    assert scans["baseline"].status == "completed"
    assert scans["current"].status == "completed"
    assert comparison.summary.persistent == 3
    assert comparison.summary.introduced == 0
    assert comparison.summary.resolved == 0
    assert comparison.summary.changed == 0
    assert comparison.delta_gate.passed is True
    assert comparison.current_gate.passed is False
    await engine.dispose()
