from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.scan import Scan
from app.services.progress import add_scan_event, latest_scan_event


async def test_latest_scan_event_tracks_pipeline_state(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/progress.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with factory() as session:
        session.add(Scan(id="scan-1", status="queued", source_type="zip", workspace_path=str(tmp_path)))
        await add_scan_event(session, "scan-1", "queued", "Waiting", percent=0)
        await add_scan_event(session, "scan-1", "reviewing", "Reviewing 2 of 4", current=2, total=4)
        await session.commit()

    async with factory() as session:
        event = await latest_scan_event(session, "scan-1")
        assert event is not None
        assert event.stage == "reviewing"
        assert event.percent == 50
        assert event.current == 2
        assert event.total == 4

    await engine.dispose()
