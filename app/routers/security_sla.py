import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.lineage import ScanLineage
from app.models.scan import Scan
from app.schemas.security_sla import (
    SecurityDebtComparison,
    SecurityDebtDashboard,
    SecuritySLADocument,
    SecuritySLAPreview,
    SecuritySLAStatus,
)
from app.services.project_context import load_context_snapshot
from app.services.risk_exception import evaluate_exception_aware_compliance, list_root_exceptions
from app.services.security_policy import (
    ensure_security_policy,
    evaluate_security_policy,
    load_policy_snapshot,
)
from app.services.security_sla import (
    build_security_debt_dashboard,
    build_security_sla_status,
    compare_security_debt,
    create_security_sla_version,
    sla_sha256,
)

router = APIRouter(prefix="/scan", tags=["security-sla"])
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


async def _root_id(db: AsyncSession, scan: Scan) -> str:
    lineage = await db.get(ScanLineage, scan.id)
    return lineage.root_scan_id if lineage else scan.id


async def _governance(scan: Scan, db: AsyncSession):
    await ensure_security_policy(db, scan)
    policy = await load_policy_snapshot(db, scan.id)
    assert policy is not None
    context = await load_context_snapshot(db, scan.id)
    raw = evaluate_security_policy(scan.id, list(scan.findings), policy, context)
    exceptions = await list_root_exceptions(db, await _root_id(db, scan))
    return evaluate_exception_aware_compliance(scan.id, list(scan.findings), raw, exceptions)


@router.get("/{scan_id}/security-sla", response_model=None)
async def get_security_sla(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan(scan_id, db)
    status = await build_security_sla_status(db, scan)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="security_sla.html",
            context={
                "scan": scan,
                "status": status,
                "document_json": json.dumps(
                    status.latest_profile.document.model_dump(mode="json"), indent=2, ensure_ascii=False
                ),
            },
        )
    return SecuritySLAStatus.model_validate(status)


@router.put("/{scan_id}/security-sla", response_model=SecuritySLAStatus)
async def create_security_sla_profile(
    scan_id: str,
    document: SecuritySLADocument,
    db: AsyncSession = Depends(get_db),
) -> SecuritySLAStatus:
    scan = await _load_scan(scan_id, db)
    await build_security_sla_status(db, scan)
    await create_security_sla_version(db, scan, document)
    await db.commit()
    return SecuritySLAStatus.model_validate(await build_security_sla_status(db, scan))


@router.post("/{scan_id}/security-sla/preview", response_model=SecuritySLAPreview)
async def preview_security_sla(
    scan_id: str,
    document: SecuritySLADocument,
    db: AsyncSession = Depends(get_db),
) -> SecuritySLAPreview:
    scan = await _load_scan(scan_id, db, finished=True)
    dashboard = await build_security_debt_dashboard(
        db,
        scan,
        governance=await _governance(scan, db),
        preview_document=document,
    )
    return SecuritySLAPreview(scan_id=scan.id, sla_sha256=sla_sha256(document), dashboard=dashboard)


@router.get("/{scan_id}/security-debt", response_model=None)
async def get_security_debt(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan(scan_id, db, finished=True)
    dashboard = await build_security_debt_dashboard(db, scan, governance=await _governance(scan, db))
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="security_debt.html",
            context={"scan": scan, "dashboard": dashboard},
        )
    return SecurityDebtDashboard.model_validate(dashboard)


@router.get(
    "/{current_scan_id}/security-debt/compare/{baseline_scan_id}",
    response_model=SecurityDebtComparison,
)
async def compare_security_debt_endpoint(
    current_scan_id: str,
    baseline_scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> SecurityDebtComparison:
    if current_scan_id == baseline_scan_id:
        raise HTTPException(status_code=422, detail="Current and baseline scans must be different")
    current = await _load_scan(current_scan_id, db, finished=True)
    baseline = await _load_scan(baseline_scan_id, db, finished=True)
    if await _root_id(db, current) != await _root_id(db, baseline):
        raise HTTPException(status_code=422, detail="Scans must belong to the same lineage")
    baseline_dashboard = await build_security_debt_dashboard(
        db, baseline, governance=await _governance(baseline, db)
    )
    current_dashboard = await build_security_debt_dashboard(
        db, current, governance=await _governance(current, db)
    )
    await db.commit()
    return compare_security_debt(baseline_dashboard, current_dashboard)
