from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.policy import evaluate_gate

router = APIRouter(prefix="/scan", tags=["judge"])
templates = Jinja2Templates(directory="app/templates")


def build_judge_metrics(findings: list[Finding]) -> dict[str, int]:
    counts = Counter()
    for finding in findings:
        if finding.llm_status == "completed":
            counts["reviewed"] += 1
        if finding.confirmed is True:
            counts["confirmed"] += 1
        elif finding.confirmed is False:
            counts["dismissed"] += 1
        if finding.confirmed and finding.patch_valid:
            counts["valid_patches"] += 1
        if finding.confirmed and finding.verification:
            counts[f"proof_{finding.verification.status}"] += 1
        if finding.confirmed and finding.decision and finding.decision.decision == "approved":
            counts["approved"] += 1
    counts["total"] = len(findings)
    counts["review_coverage"] = round((counts["reviewed"] / len(findings)) * 100) if findings else 100
    return dict(counts)


def _ordered_findings(findings: list[Finding]) -> list[Finding]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda item: (order.get(item.severity or "", 4), item.file_path, item.line))


@router.get("/{scan_id}/judge", response_model=None)
async def get_judge_view(
    request: Request,
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
        )
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")

    findings = _ordered_findings(scan.findings)
    gate = evaluate_gate(scan.id, findings)
    metrics = build_judge_metrics(findings)
    return templates.TemplateResponse(
        request=request,
        name="judge.html",
        context={"scan": scan, "findings": findings, "gate": gate, "metrics": metrics},
    )
