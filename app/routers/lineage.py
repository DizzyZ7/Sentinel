from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.lineage import CIGateResponse, LineageResponse
from app.services.comparison import build_scan_comparison
from app.services.lineage import build_lineage_response, resolve_baseline_scan_id

router = APIRouter(prefix="/scan", tags=["lineage"])


def _scan_query(scan_id: str):
    return (
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
        )
        .where(Scan.id == scan_id)
    )


async def _load_scan(scan_id: str, db: AsyncSession, *, finished: bool = False) -> Scan:
    result = await db.execute(_scan_query(scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if finished and scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan {scan_id} is still {scan.status}")
    return scan


@router.get("/{scan_id}/lineage", response_model=LineageResponse)
async def get_scan_lineage(scan_id: str, db: AsyncSession = Depends(get_db)) -> LineageResponse:
    scan = await _load_scan(scan_id, db)
    return await build_lineage_response(db, scan)


@router.get("/{current_scan_id}/ci-gate", response_model=None)
async def get_ci_gate(
    current_scan_id: str,
    baseline_scan_id: str | None = Query(default=None),
    block_on: Literal["critical", "high", "medium", "low"] = Query(default="high"),
    fail_closed_on_unreviewed: bool = Query(default=True),
    db: AsyncSession = Depends(get_db),
):
    current = await _load_scan(current_scan_id, db, finished=True)
    lineage = await build_lineage_response(db, current)
    resolved_baseline_id = await resolve_baseline_scan_id(db, current, baseline_scan_id)
    if not resolved_baseline_id:
        raise HTTPException(
            status_code=422,
            detail="No baseline is linked to this scan; provide baseline_scan_id or create a rescan first",
        )

    eligible = {node.scan_id for node in lineage.nodes if node.eligible_baseline}
    if resolved_baseline_id not in eligible:
        raise HTTPException(status_code=422, detail="Baseline must be an earlier completed scan in the same lineage")

    baseline = await _load_scan(resolved_baseline_id, db, finished=True)
    comparison = build_scan_comparison(
        baseline,
        current,
        block_on=block_on,
        fail_closed_on_unreviewed=fail_closed_on_unreviewed,
    )
    payload = CIGateResponse(
        current_scan_id=current.id,
        baseline_scan_id=baseline.id,
        state=comparison.delta_gate.state,
        passed=comparison.delta_gate.passed,
        exit_code=0 if comparison.delta_gate.passed else 1,
        block_on=block_on,
        fail_closed_on_unreviewed=fail_closed_on_unreviewed,
        summary=comparison.summary,
        blockers=comparison.delta_gate.blockers,
        comparison_url=f"/scan/{current.id}/compare/{baseline.id}?format=html",
    )
    return JSONResponse(
        status_code=200 if payload.passed else 409,
        content=payload.model_dump(mode="json"),
        headers={"X-Sentinel-Exit-Code": str(payload.exit_code)},
    )
