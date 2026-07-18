from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.llm_audit import LLMReviewRunResponse
from app.services.llm_audit import build_llm_audit_response

router = APIRouter(prefix="/scan", tags=["llm-audit"])
templates = Jinja2Templates(directory="app/templates")


async def _load_scan_with_reviews(scan_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.findings).selectinload(Finding.llm_review))
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")
    return scan


@router.get("/{scan_id}/llm-reviews", response_model=None)
async def get_llm_reviews(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan_with_reviews(scan_id, db)
    findings = sorted(scan.findings, key=lambda item: (item.file_path, item.line))
    payload = build_llm_audit_response(scan.id, findings)
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        reviews_by_finding = {review.finding_id: review for review in payload.reviews}
        rows = [
            {
                "finding": finding,
                "review": reviews_by_finding.get(finding.id),
            }
            for finding in findings
        ]
        return templates.TemplateResponse(
            request=request,
            name="llm_audit.html",
            context={"scan": scan, "audit": payload.model_dump(mode="json"), "rows": rows},
        )
    return payload


@router.get(
    "/{scan_id}/findings/{finding_id}/llm-review",
    response_model=LLMReviewRunResponse,
)
async def get_finding_llm_review(
    scan_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> LLMReviewRunResponse:
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.llm_review))
        .where(Finding.id == finding_id, Finding.scan_id == scan_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.llm_review:
        raise HTTPException(status_code=404, detail="GPT review audit not available")
    return LLMReviewRunResponse.model_validate(finding.llm_review)
