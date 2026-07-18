from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.risk_intelligence import ExecutiveReport, RiskIntelligenceResponse
from app.services.project_context import load_context_snapshot
from app.services.risk_intelligence import build_executive_report, build_risk_intelligence

router = APIRouter(prefix="/scan", tags=["risk-intelligence"])
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


async def _load_finished_scan(scan_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(_scan_query(scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")
    return scan


@router.get("/{scan_id}/risk-intelligence", response_model=list[RiskIntelligenceResponse])
async def get_scan_risk_intelligence(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[RiskIntelligenceResponse]:
    scan = await _load_finished_scan(scan_id, db)
    context = await load_context_snapshot(db, scan.id)
    rows = []
    for finding in scan.findings:
        risk = finding.risk_intelligence or build_risk_intelligence(finding, context)
        if risk is not None:
            rows.append(RiskIntelligenceResponse.model_validate(risk))
    return sorted(rows, key=lambda item: (-item.residual_risk_score, item.finding_id))


@router.get(
    "/{scan_id}/findings/{finding_id}/risk-intelligence",
    response_model=RiskIntelligenceResponse,
)
async def get_finding_risk_intelligence(
    scan_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> RiskIntelligenceResponse:
    scan = await _load_finished_scan(scan_id, db)
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    context = await load_context_snapshot(db, scan.id)
    risk = finding.risk_intelligence or build_risk_intelligence(finding, context)
    if risk is None:
        raise HTTPException(status_code=409, detail="Risk intelligence requires a confirmed finding")
    return RiskIntelligenceResponse.model_validate(risk)


@router.get("/{scan_id}/executive-report", response_model=None)
async def get_executive_report(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_finished_scan(scan_id, db)
    context = await load_context_snapshot(db, scan.id)
    report = build_executive_report(scan.id, list(scan.findings), context)
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="executive_report.html",
            context={"scan": scan, "report": report},
        )
    return ExecutiveReport.model_validate(report)
