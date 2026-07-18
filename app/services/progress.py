from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_event import ScanEvent


async def add_scan_event(
    session: AsyncSession,
    scan_id: str,
    stage: str,
    message: str,
    *,
    current: int = 0,
    total: int = 1,
    percent: int | None = None,
    status: str = "active",
) -> ScanEvent:
    safe_total = max(total, 1)
    safe_current = max(0, min(current, safe_total))
    calculated = round((safe_current / safe_total) * 100) if percent is None else percent
    event = ScanEvent(
        scan_id=scan_id,
        stage=stage,
        status=status,
        current=safe_current,
        total=safe_total,
        percent=max(0, min(calculated, 100)),
        message=message[:1000],
    )
    session.add(event)
    return event


async def latest_scan_event(session: AsyncSession, scan_id: str) -> ScanEvent | None:
    result = await session.execute(
        select(ScanEvent)
        .where(ScanEvent.scan_id == scan_id)
        .order_by(desc(ScanEvent.created_at), desc(ScanEvent.id))
        .limit(1)
    )
    return result.scalar_one_or_none()
