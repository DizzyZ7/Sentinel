from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.security_posture import SecurityPostureTrend
from app.services.security_posture import build_security_posture_trend

router = APIRouter(prefix="/scan", tags=["security-posture"])
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


@router.get("/{scan_id}/security-posture", response_model=None)
async def get_security_posture(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(_scan_query(scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")
    trend = await build_security_posture_trend(db, scan)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="security_posture.html",
            context={"scan": scan, "trend": trend},
        )
    return SecurityPostureTrend.model_validate(trend)
