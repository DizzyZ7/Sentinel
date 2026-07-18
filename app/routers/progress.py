from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.scan import Scan
from app.models.scan_event import ScanEvent
from app.schemas.progress import ScanEventResponse, ScanProgress
from app.schemas.scan import ScanStatus
from app.services.progress import latest_scan_event

router = APIRouter(prefix="/scan", tags=["progress"])


@router.get("/{scan_id}/progress", response_model=ScanStatus)
async def get_scan_progress(scan_id: str, db: AsyncSession = Depends(get_db)) -> ScanStatus:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    event = await latest_scan_event(db, scan.id)
    payload = ScanStatus.model_validate(scan).model_dump()
    payload["progress"] = ScanProgress.model_validate(event) if event else None
    return ScanStatus(**payload)


@router.get("/{scan_id}/events", response_model=list[ScanEventResponse])
async def get_scan_events(scan_id: str, db: AsyncSession = Depends(get_db)) -> list[ScanEventResponse]:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = await db.execute(
        select(ScanEvent)
        .where(ScanEvent.scan_id == scan_id)
        .order_by(ScanEvent.created_at, ScanEvent.id)
    )
    return [ScanEventResponse.model_validate(event) for event in result.scalars()]
