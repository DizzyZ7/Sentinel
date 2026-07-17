import re
import uuid
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models.scan import Scan
from app.schemas.finding import FindingResponse
from app.schemas.scan import ReportResponse, ScanCreated, ScanStatus, SeveritySummary
from app.services.ingestion import IngestionError, save_upload, validate_git_url
from app.services.reporting import severity_summary
from app.services.scanner import process_scan

router = APIRouter(prefix="/scan", tags=["scans"])
templates = Jinja2Templates(directory="app/templates")
SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _scan_created(scan: Scan) -> ScanCreated:
    return ScanCreated(
        scan_id=scan.id,
        status=scan.status,
        status_url=f"/scan/{scan.id}",
        report_url=f"/scan/{scan.id}/report",
    )


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
            source_url = validate_git_url(git_url, settings.allowed_git_hosts)
            scan = Scan(
                id=scan_id,
                status="queued",
                source_type="git",
                source_url=source_url,
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
                status="queued",
                source_type="zip",
                original_filename=filename,
                workspace_path=str(workspace),
            )
    except IngestionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    db.add(scan)
    await db.commit()
    background_tasks.add_task(process_scan, scan.id)
    return _scan_created(scan)


@router.get("/{scan_id}", response_model=ScanStatus)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> ScanStatus:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatus.model_validate(scan)


@router.get("/{scan_id}/report", response_model=None)
async def get_report(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")

    ordered_findings = sorted(
        scan.findings,
        key=lambda finding: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(finding.severity or "", 4),
            finding.file_path,
            finding.line,
        ),
    )
    confirmed_severities = [
        finding.severity for finding in ordered_findings if finding.confirmed and finding.severity is not None
    ]
    payload = ReportResponse(
        **ScanStatus.model_validate(scan).model_dump(),
        severity_summary=SeveritySummary(**severity_summary(confirmed_severities)),
        findings=[FindingResponse.model_validate(item) for item in ordered_findings],
        structure=scan.structure,
    )

    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="report.html",
            context={"report": payload.model_dump(mode="json")},
        )
    return payload


@router.get("", response_model=list[ScanStatus])
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> list[ScanStatus]:
    result = await db.execute(select(Scan).order_by(desc(Scan.created_at)).limit(limit))
    return [ScanStatus.model_validate(scan) for scan in result.scalars()]
