from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.scan import Scan
from app.services.lineage import build_lineage_response, ensure_root_lineage, link_rescan


async def test_lineage_persists_root_parent_generation_and_baseline_choices(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/lineage.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    now = datetime.now(UTC)
    root = Scan(
        id="root",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(tmp_path / "root"),
        created_at=now,
        completed_at=now,
        risk_score=70.0,
        finding_count=3,
    )
    child = Scan(
        id="child",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(tmp_path / "child"),
        created_at=now + timedelta(minutes=1),
        completed_at=now + timedelta(minutes=1),
        risk_score=50.0,
        finding_count=2,
    )
    grandchild = Scan(
        id="grandchild",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(tmp_path / "grandchild"),
        created_at=now + timedelta(minutes=2),
        completed_at=now + timedelta(minutes=2),
        risk_score=20.0,
        finding_count=1,
    )

    async with factory() as session:
        session.add(root)
        await session.flush()
        await ensure_root_lineage(session, root)
        session.add(child)
        await session.flush()
        await link_rescan(session, root, child)
        session.add(grandchild)
        await session.flush()
        await link_rescan(session, child, grandchild)
        await session.commit()

    async with factory() as session:
        current = await session.get(Scan, "grandchild")
        assert current is not None
        lineage = await build_lineage_response(session, current)

    assert lineage.root_scan_id == "root"
    assert lineage.parent_scan_id == "child"
    assert lineage.default_baseline_scan_id == "child"
    assert [(node.scan_id, node.generation) for node in lineage.nodes] == [
        ("root", 0),
        ("child", 1),
        ("grandchild", 2),
    ]
    assert {node.scan_id for node in lineage.nodes if node.eligible_baseline} == {"root", "child"}
    await engine.dispose()
