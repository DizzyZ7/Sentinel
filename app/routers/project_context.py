import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.project_context import (
    ProjectContextDocument,
    ProjectContextPreview,
    ProjectContextStatus,
)
from app.services.project_context import (
    ProjectContextSnapshot,
    build_project_context_status,
    context_sha256,
    create_project_context_version,
)
from app.services.risk_intelligence import build_executive_report

router = APIRouter(prefix="/scan", tags=["project-context"])
templates = Jinja2Templates(directory="app/templates")


def _scan_query(scan_id: str):
    return (
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
            selectinload(Scan.findings).selectinload(Finding.risk_intelligence),
        )
        .where(Scan.id == scan_id)
    )


async def _load_scan(scan_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(_scan_query(scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/project-context", response_model=None)
async def get_project_context(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan(scan_id, db)
    status = await build_project_context_status(db, scan)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="project_context.html",
            context={
                "scan": scan,
                "status": status,
                "document_json": json.dumps(
                    status.latest_profile.document.model_dump(mode="json"), indent=2, ensure_ascii=False
                ),
            },
        )
    return ProjectContextStatus.model_validate(status)


@router.put("/{scan_id}/project-context", response_model=ProjectContextStatus)
async def create_project_context_profile(
    scan_id: str,
    document: ProjectContextDocument,
    db: AsyncSession = Depends(get_db),
) -> ProjectContextStatus:
    scan = await _load_scan(scan_id, db)
    await build_project_context_status(db, scan)
    await create_project_context_version(db, scan, document)
    await db.commit()
    status = await build_project_context_status(db, scan)
    return ProjectContextStatus.model_validate(status)


@router.post("/{scan_id}/project-context/preview", response_model=ProjectContextPreview)
async def preview_project_context(
    scan_id: str,
    document: ProjectContextDocument,
    db: AsyncSession = Depends(get_db),
) -> ProjectContextPreview:
    scan = await _load_scan(scan_id, db)
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")
    digest = context_sha256(document)
    snapshot = ProjectContextSnapshot(
        profile_id="preview",
        root_scan_id=scan.id,
        version=0,
        source="preview",
        context_sha256=digest,
        document=document,
    )
    report = build_executive_report(scan.id, list(scan.findings), snapshot)
    return ProjectContextPreview(scan_id=scan.id, context_sha256=digest, report=report)
