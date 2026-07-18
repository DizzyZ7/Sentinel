import uuid
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.comparison import RescanCreated, ScanComparison
from app.services.comparison import build_scan_comparison
from app.services.demo_reviewer import DemoReviewer
from app.services.progress import add_scan_event
from app.services.rescan import RescanError, prepare_rescan
from app.services.scanner import process_scan

router = APIRouter(prefix="/scan", tags=["comparison"])
templates = Jinja2Templates(directory="app/templates")


def _comparison_query(scan_id: str):
    return (
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
        )
        .where(Scan.id == scan_id)
    )


async def _load_finished_scan(scan_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(_comparison_query(scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan {scan_id} is still {scan.status}")
    return scan


@router.post("/{baseline_scan_id}/rescan", response_model=RescanCreated, status_code=status.HTTP_202_ACCEPTED)
async def create_rescan(
    baseline_scan_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RescanCreated:
    baseline = await _load_finished_scan(baseline_scan_id, db)
    scan_id = str(uuid.uuid4())
    try:
        scan = prepare_rescan(baseline, scan_id, settings)
    except RescanError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    db.add(scan)
    await add_scan_event(
        db,
        scan.id,
        "queued",
        f"Rescan queued from baseline {baseline.id}; comparison will be available after completion.",
        percent=0,
    )
    await db.commit()

    reviewer = None
    if baseline.original_filename and "sentinel-judge-demo-replay" in baseline.original_filename:
        reviewer = DemoReviewer(settings)
    background_tasks.add_task(process_scan, scan.id, reviewer)
    return RescanCreated(
        scan_id=scan.id,
        baseline_scan_id=baseline.id,
        status=scan.status,
        status_url=f"/scan/{scan.id}",
        report_url=f"/scan/{scan.id}/judge",
        comparison_url=f"/scan/{scan.id}/compare/{baseline.id}?format=html",
    )


@router.get("/{current_scan_id}/compare/{baseline_scan_id}", response_model=None)
async def compare_scans(
    request: Request,
    current_scan_id: str,
    baseline_scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    block_on: Literal["critical", "high", "medium", "low"] = Query(default="high"),
    fail_closed_on_unreviewed: bool = Query(default=True),
    db: AsyncSession = Depends(get_db),
):
    if current_scan_id == baseline_scan_id:
        raise HTTPException(status_code=422, detail="Current and baseline scans must be different")
    baseline = await _load_finished_scan(baseline_scan_id, db)
    current = await _load_finished_scan(current_scan_id, db)
    comparison = build_scan_comparison(
        baseline,
        current,
        block_on=block_on,
        fail_closed_on_unreviewed=fail_closed_on_unreviewed,
    )
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="comparison.html",
            context={"baseline": baseline, "current": current, "comparison": comparison},
        )
    return ScanComparison.model_validate(comparison)
