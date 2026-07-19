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
from app.schemas.security_objective import (
    SecurityObjectiveDocument,
    SecurityObjectivePreview,
    SecurityObjectiveReport,
    SecurityObjectiveStatus,
)
from app.services.security_objective import (
    build_security_objective_report,
    build_security_objective_status,
    create_security_objective_version,
    preview_security_objective,
)

router = APIRouter(prefix="/scan", tags=["security-objectives"])
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


async def _load_scan(scan_id: str, db: AsyncSession, *, finished: bool = False) -> Scan:
    result = await db.execute(_scan_query(scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if finished and scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")
    return scan


@router.get("/{scan_id}/security-objectives", response_model=None)
async def get_security_objectives(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan(scan_id, db)
    status = await build_security_objective_status(db, scan)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="security_objectives.html",
            context={
                "scan": scan,
                "status": status,
                "document_json": json.dumps(
                    status.latest_profile.document.model_dump(mode="json"), indent=2, ensure_ascii=False
                ),
            },
        )
    return SecurityObjectiveStatus.model_validate(status)


@router.put("/{scan_id}/security-objectives", response_model=SecurityObjectiveStatus)
async def create_security_objective_profile(
    scan_id: str,
    document: SecurityObjectiveDocument,
    db: AsyncSession = Depends(get_db),
) -> SecurityObjectiveStatus:
    scan = await _load_scan(scan_id, db)
    await build_security_objective_status(db, scan)
    await create_security_objective_version(db, scan, document)
    await db.commit()
    return SecurityObjectiveStatus.model_validate(await build_security_objective_status(db, scan))


@router.post("/{scan_id}/security-objectives/preview", response_model=SecurityObjectivePreview)
async def preview_security_objectives(
    scan_id: str,
    document: SecurityObjectiveDocument,
    db: AsyncSession = Depends(get_db),
) -> SecurityObjectivePreview:
    scan = await _load_scan(scan_id, db, finished=True)
    return await preview_security_objective(db, scan, document)


@router.get("/{scan_id}/objective-report", response_model=None)
async def get_security_objective_report(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan(scan_id, db, finished=True)
    report = await build_security_objective_report(db, scan)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="security_objective_report.html",
            context={"scan": scan, "report": report},
        )
    return SecurityObjectiveReport.model_validate(report)
