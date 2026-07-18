from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.scan_event import ScanEvent
from app.services.demo_fixture import create_judge_demo_archive
from app.services.demo_reviewer import DemoReviewer
from app.services.policy import evaluate_gate
from app.services.scanner import process_scan


async def test_golden_pipeline_covers_confirm_reject_and_failed_proof(tmp_path: Path) -> None:
    database_url = f"sqlite+aiosqlite:///{tmp_path}/golden.db"
    engine = create_async_engine(database_url)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    settings = Settings(database_url=database_url, data_dir=tmp_path / "data", openai_api_key=None)
    workspace = settings.scans_dir / "golden-scan"
    workspace.mkdir(parents=True)
    create_judge_demo_archive(workspace / "source.zip")

    async with factory() as session:
        session.add(
            Scan(
                id="golden-scan",
                status="queued",
                source_type="zip",
                original_filename="sentinel-judge-demo-replay.zip",
                workspace_path=str(workspace),
            )
        )
        await session.commit()

    await process_scan(
        "golden-scan",
        reviewer=DemoReviewer(settings),
        session_factory=factory,
        pipeline_settings=settings,
    )

    async with factory() as session:
        result = await session.execute(
            select(Scan)
            .options(
                selectinload(Scan.findings).selectinload(Finding.verification),
                selectinload(Scan.findings).selectinload(Finding.llm_review),
                selectinload(Scan.findings).selectinload(Finding.decision),
                selectinload(Scan.findings).selectinload(Finding.risk_intelligence),
            )
            .where(Scan.id == "golden-scan")
        )
        scan = result.scalar_one()
        findings = {finding.file_path: finding for finding in scan.findings}

        assert scan.status == "completed"
        assert sum(finding.risk_intelligence is not None for finding in scan.findings) == 2
        assert scan.candidate_count == 3
        assert scan.finding_count == 2

        verified = findings["confirmed_sql.py"]
        assert verified.confirmed is True
        assert verified.patch_valid is True
        assert verified.verification and verified.verification.status == "passed"

        rejected = findings["safe_constant.py"]
        assert rejected.confirmed is False
        assert rejected.llm_review and rejected.llm_review.model == "sentinel-deterministic-demo-replay"

        blocked = findings["weak_patch.py"]
        assert blocked.confirmed is True
        assert blocked.patch_valid is True
        assert blocked.verification and blocked.verification.status == "failed"

        gate = evaluate_gate(scan.id, scan.findings)
        assert gate.passed is False
        assert {item.finding_id for item in gate.blockers} == {verified.id, blocked.id}

        events = list(
            (
                await session.execute(
                    select(ScanEvent)
                    .where(ScanEvent.scan_id == scan.id)
                    .order_by(ScanEvent.created_at, ScanEvent.id)
                )
            ).scalars()
        )
        assert events[0].stage == "ingesting"
        assert events[-1].stage == "completed"
        assert events[-1].percent == 100
        assert any(event.stage == "reviewing" and event.current == 3 for event in events)

    await engine.dispose()
