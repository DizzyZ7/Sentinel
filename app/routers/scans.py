import re
import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models.scan import Scan
from app.schemas.scan import ScanCreated, ScanStatus
from app.services.ingestion import IngestionError, save_upload, validate_git_url
from app.services.scanner import process_scan

router = APIRouter(prefix="/scan", tags=["scans"])
SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


@router.post("/repo", response_model=ScanCreated, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    background_tasks: BackgroundTasks,
    git_url: Annotated[str | None, Form()] = None,
    archive: Annotated[UploadFile | None, File()] = None,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ScanCreated:
    if bool(git_url) == bool(archive):
        raise HTTPException(status_code=422, detail="Provide exactly one of git_url or archive")
    scan_id = str(uuid.uuid4())
    workspace = settings.scans_dir / scan_id
    workspace.mkdir(parents=True, exist_ok=False)
    try:
        if git_url:
            scan = Scan(
                id=scan_id,
                source_type="git",
                source_url=validate_git_url(git_url, settings.allowed_git_hosts),
                workspace_path=str(workspace),
            )
        else:
            assert archive is not None
            filename = SAFE_FILENAME_RE.sub("_", archive.filename or "repository.zip")
            if not filename.lower().endswith(".zip"):
                raise IngestionError("Only .zip archives are supported")
            await save_upload(archive, workspace / "source.zip", settings.max_archive_bytes)
            scan = Scan(
                id=scan_id,
                source_type="zip",
                original_filename=filename,
                workspace_path=str(workspace),
            )
    except IngestionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.add(scan)
    await db.commit()
    background_tasks.add_task(process_scan, scan.id)
    return ScanCreated(
        scan_id=scan.id,
        status=scan.status,
        status_url=f"/scan/{scan.id}",
        report_url=f"/scan/{scan.id}/report",
    )


@router.get("/{scan_id}", response_model=ScanStatus)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> ScanStatus:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatus.model_validate(scan)
