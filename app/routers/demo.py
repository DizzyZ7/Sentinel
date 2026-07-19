import uuid
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models.scan import Scan
from app.schemas.scan import ScanCreated
from app.services.demo_fixture import create_judge_demo_archive
from app.services.demo_reviewer import DemoReviewer
from app.services.lineage import ensure_root_lineage
from app.services.progress import add_scan_event
from app.services.project_context import demo_project_context, ensure_project_context
from app.services.scanner import process_scan
from app.services.security_objective import demo_security_objective, ensure_security_objective
from app.services.security_policy import demo_security_policy, ensure_security_policy
from app.services.security_sla import demo_security_sla, ensure_security_sla

router = APIRouter(prefix="/scan", tags=["demo"])


@router.post("/demo", response_model=ScanCreated, status_code=status.HTTP_202_ACCEPTED)
async def create_demo_scan(
    background_tasks: BackgroundTasks,
    mode: Literal["replay", "live"] = Query(default="replay"),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ScanCreated:
    if mode == "live" and not settings.openai_api_key:
        raise HTTPException(status_code=409, detail="OPENAI_API_KEY is required for the live GPT-5.6 demo")

    scan_id = str(uuid.uuid4())
    workspace = settings.scans_dir / scan_id
    workspace.mkdir(parents=True, exist_ok=False)
    try:
        create_judge_demo_archive(workspace / "source.zip")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    scan = Scan(
        id=scan_id,
        status="queued",
        source_type="zip",
        original_filename=(
            "sentinel-judge-demo-live-gpt.zip" if mode == "live" else "sentinel-judge-demo-replay.zip"
        ),
        workspace_path=str(workspace),
    )
    db.add(scan)
    await db.flush()
    await ensure_root_lineage(db, scan)
    await ensure_project_context(db, scan, demo_project_context(), source="built_in")
    await ensure_security_policy(db, scan, demo_security_policy(), source="built_in")
    await ensure_security_sla(db, scan, demo_security_sla(), source="built_in")
    await ensure_security_objective(db, scan, demo_security_objective(scan), source="built_in")
    await add_scan_event(
        db,
        scan.id,
        "queued",
        (
            "Built-in demo queued for live GPT-5.6 review."
            if mode == "live"
            else "Built-in deterministic demo replay queued; no external model call will be made."
        ),
        percent=0,
    )
    await db.commit()

    reviewer = None if mode == "live" else DemoReviewer(settings)
    background_tasks.add_task(process_scan, scan.id, reviewer)
    return ScanCreated(
        scan_id=scan.id,
        status=scan.status,
        status_url=f"/scan/{scan.id}",
        report_url=f"/scan/{scan.id}/judge",
    )
