from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.lineage import ScanLineage
from app.models.risk_exception import RiskException
from app.models.scan import Scan
from app.schemas.risk_exception import (
    ExceptionAwareCompliance,
    ExceptionDebtComparison,
    RiskExceptionCreate,
    RiskExceptionDecisionRequest,
    RiskExceptionList,
    RiskExceptionResponse,
    RiskExceptionRevokeRequest,
)
from app.services.project_context import load_context_snapshot
from app.services.risk_exception import (
    build_exception_list,
    compare_exception_debt,
    create_risk_exception,
    decide_risk_exception,
    evaluate_exception_aware_compliance,
    list_root_exceptions,
    revoke_risk_exception,
)
from app.services.security_policy import (
    ensure_security_policy,
    evaluate_security_policy,
    load_policy_snapshot,
)

router = APIRouter(prefix="/scan", tags=["risk-exceptions"])
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


async def _root_scan_id(db: AsyncSession, scan: Scan) -> str:
    lineage = await db.get(ScanLineage, scan.id)
    return lineage.root_scan_id if lineage else scan.id


async def _raw_compliance(scan: Scan, db: AsyncSession):
    await ensure_security_policy(db, scan)
    policy = await load_policy_snapshot(db, scan.id)
    assert policy is not None
    context = await load_context_snapshot(db, scan.id)
    return evaluate_security_policy(scan.id, list(scan.findings), policy, context)


async def _governance(
    scan: Scan,
    db: AsyncSession,
    *,
    at: datetime | None = None,
) -> ExceptionAwareCompliance:
    raw = await _raw_compliance(scan, db)
    root_scan_id = await _root_scan_id(db, scan)
    exceptions = await list_root_exceptions(db, root_scan_id)
    return evaluate_exception_aware_compliance(
        scan.id,
        list(scan.findings),
        raw,
        exceptions,
        at=at,
    )


async def _load_exception_for_scan(
    scan: Scan,
    exception_id: str,
    db: AsyncSession,
) -> RiskException:
    item = await db.get(RiskException, exception_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Risk exception not found")
    if item.root_scan_id != await _root_scan_id(db, scan):
        raise HTTPException(status_code=404, detail="Risk exception not found in this lineage")
    return item


@router.get("/{scan_id}/risk-exceptions", response_model=None)
async def get_risk_exceptions(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan(scan_id, db)
    payload = await build_exception_list(db, scan)
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="risk_exceptions.html",
            context={"scan": scan, "payload": payload},
        )
    return RiskExceptionList.model_validate(payload)


@router.post("/{scan_id}/risk-exceptions", response_model=RiskExceptionResponse, status_code=201)
async def request_risk_exception(
    scan_id: str,
    body: RiskExceptionCreate,
    db: AsyncSession = Depends(get_db),
) -> RiskExceptionResponse:
    scan = await _load_scan(scan_id, db, finished=True)
    context = await load_context_snapshot(db, scan.id)
    try:
        item = await create_risk_exception(db, scan, body, context)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    await db.commit()
    payload = await build_exception_list(db, scan)
    return next(entry for entry in payload.exceptions if entry.id == item.id)


@router.post(
    "/{scan_id}/risk-exceptions/{exception_id}/decision",
    response_model=RiskExceptionResponse,
)
async def decide_exception(
    scan_id: str,
    exception_id: str,
    body: RiskExceptionDecisionRequest,
    db: AsyncSession = Depends(get_db),
) -> RiskExceptionResponse:
    scan = await _load_scan(scan_id, db)
    item = await _load_exception_for_scan(scan, exception_id, db)
    try:
        await decide_risk_exception(db, item, body)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await db.commit()
    payload = await build_exception_list(db, scan)
    return next(entry for entry in payload.exceptions if entry.id == item.id)


@router.post(
    "/{scan_id}/risk-exceptions/{exception_id}/revoke",
    response_model=RiskExceptionResponse,
)
async def revoke_exception(
    scan_id: str,
    exception_id: str,
    body: RiskExceptionRevokeRequest,
    db: AsyncSession = Depends(get_db),
) -> RiskExceptionResponse:
    scan = await _load_scan(scan_id, db)
    item = await _load_exception_for_scan(scan, exception_id, db)
    try:
        await revoke_risk_exception(db, item, body)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await db.commit()
    payload = await build_exception_list(db, scan)
    return next(entry for entry in payload.exceptions if entry.id == item.id)


@router.get("/{scan_id}/exception-aware-compliance", response_model=None)
async def get_exception_aware_compliance(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan(scan_id, db, finished=True)
    payload = await _governance(scan, db)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="exception_compliance.html",
            context={"scan": scan, "governance": payload},
        )
    return ExceptionAwareCompliance.model_validate(payload)


@router.get(
    "/{current_scan_id}/exception-debt/compare/{baseline_scan_id}",
    response_model=ExceptionDebtComparison,
)
async def compare_exception_debt_endpoint(
    current_scan_id: str,
    baseline_scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> ExceptionDebtComparison:
    if current_scan_id == baseline_scan_id:
        raise HTTPException(status_code=422, detail="Current and baseline scans must be different")
    current = await _load_scan(current_scan_id, db, finished=True)
    baseline = await _load_scan(baseline_scan_id, db, finished=True)
    current_root = await _root_scan_id(db, current)
    baseline_root = await _root_scan_id(db, baseline)
    if current_root != baseline_root:
        raise HTTPException(status_code=422, detail="Scans must belong to the same lineage")
    exceptions = await list_root_exceptions(db, current_root)
    baseline_as_of = baseline.completed_at or baseline.created_at
    current_as_of = current.completed_at or datetime.now(UTC)
    baseline_governance = await _governance(baseline, db, at=baseline_as_of)
    current_governance = await _governance(current, db, at=current_as_of)
    return compare_exception_debt(
        baseline.id,
        current.id,
        exceptions,
        baseline_governance,
        current_governance,
        baseline_as_of=baseline_as_of,
        current_as_of=current_as_of,
    )
