from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.evidence import build_finding_evidence_bundle

router = APIRouter(prefix="/scan", tags=["evidence"])


@router.get("/{scan_id}/findings/{finding_id}/evidence-bundle", response_model=None)
async def get_finding_evidence_bundle(
    scan_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    result = await db.execute(
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
            selectinload(Scan.findings).selectinload(Finding.llm_review),
            selectinload(Scan.findings).selectinload(Finding.risk_intelligence),
        )
        .where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")
    finding = next((item for item in scan.findings if item.id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    ordered_findings = sorted(scan.findings, key=lambda item: (item.file_path, item.line))
    bundle = build_finding_evidence_bundle(scan, finding, ordered_findings)
    return JSONResponse(
        bundle.model_dump(mode="json"),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="sentinel-evidence-{finding.id}.json"',
            "X-Sentinel-Evidence-SHA256": bundle.integrity.payload_sha256,
        },
    )
