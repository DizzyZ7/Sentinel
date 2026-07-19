import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.portfolio import SecurityPortfolio
from app.schemas.control_plane import (
    AlertAcknowledgeRequest,
    AlertResolveRequest,
    ControlPlaneChainVerification,
    PortfolioAlertResponse,
    PortfolioAuditEventResponse,
    PortfolioControlDocument,
    PortfolioControlPlaneEvidence,
    PortfolioControlPlaneSchedule,
    PortfolioControlStatus,
    PortfolioSnapshotDetail,
    PortfolioSnapshotSummary,
    SnapshotCaptureRequest,
)
from app.services.control_plane import (
    acknowledge_alert,
    alert_response,
    build_control_plane_evidence,
    build_schedule_status,
    build_timeline,
    capture_snapshot,
    control_status,
    create_control_profile_version,
    get_snapshot,
    list_alerts,
    list_audit_events,
    list_snapshots,
    resolve_alert,
    snapshot_detail,
    verify_control_plane_chains,
)

router = APIRouter(prefix="/portfolios", tags=["continuous-control-plane"])
templates = Jinja2Templates(directory="app/templates")


async def _load_portfolio(portfolio_id: str, db: AsyncSession) -> SecurityPortfolio:
    portfolio = await db.get(SecurityPortfolio, portfolio_id)
    if portfolio is None:
        raise HTTPException(status_code=404, detail="Portfolio not found")
    return portfolio


@router.get("/{portfolio_id}/control-plane", response_model=PortfolioControlStatus)
async def get_control_plane(
    portfolio_id: str,
    db: AsyncSession = Depends(get_db),
) -> PortfolioControlStatus:
    portfolio = await _load_portfolio(portfolio_id, db)
    result = await control_status(db, portfolio)
    await db.commit()
    return result


@router.put("/{portfolio_id}/control-plane", response_model=PortfolioControlStatus)
async def put_control_plane(
    portfolio_id: str,
    document: PortfolioControlDocument,
    actor: str = Query(default="local-operator", min_length=1, max_length=180),
    db: AsyncSession = Depends(get_db),
) -> PortfolioControlStatus:
    portfolio = await _load_portfolio(portfolio_id, db)
    await create_control_profile_version(db, portfolio, document, actor=actor)
    await db.commit()
    return await control_status(db, portfolio)


@router.get("/{portfolio_id}/control-plane/status", response_model=PortfolioControlPlaneSchedule)
async def get_control_plane_schedule(
    portfolio_id: str,
    db: AsyncSession = Depends(get_db),
) -> PortfolioControlPlaneSchedule:
    portfolio = await _load_portfolio(portfolio_id, db)
    result = await build_schedule_status(db, portfolio)
    await db.commit()
    return result


@router.post("/{portfolio_id}/snapshots", response_model=None)
async def post_portfolio_snapshot(
    portfolio_id: str,
    request: SnapshotCaptureRequest,
    db: AsyncSession = Depends(get_db),
):
    portfolio = await _load_portfolio(portfolio_id, db)
    try:
        result = await capture_snapshot(db, portfolio, request)
        await db.commit()
        code = status.HTTP_201_CREATED if result.created else status.HTTP_200_OK
        return JSONResponse(result.model_dump(mode="json"), status_code=code)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{portfolio_id}/snapshots", response_model=list[PortfolioSnapshotSummary])
async def get_portfolio_snapshots(
    portfolio_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[PortfolioSnapshotSummary]:
    await _load_portfolio(portfolio_id, db)
    return await list_snapshots(db, portfolio_id)


@router.get("/{portfolio_id}/snapshots/{snapshot_id}", response_model=PortfolioSnapshotDetail)
async def get_portfolio_snapshot(
    portfolio_id: str,
    snapshot_id: str,
    db: AsyncSession = Depends(get_db),
) -> PortfolioSnapshotDetail:
    await _load_portfolio(portfolio_id, db)
    row = await get_snapshot(db, portfolio_id, snapshot_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Portfolio snapshot not found")
    return snapshot_detail(row)


@router.get("/{portfolio_id}/timeline", response_model=None)
async def get_portfolio_timeline(
    request: Request,
    portfolio_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    portfolio = await _load_portfolio(portfolio_id, db)
    timeline = await build_timeline(db, portfolio)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="control_plane.html",
            context={
                "portfolio": portfolio,
                "timeline": timeline,
                "control_json": json.dumps(
                    timeline.control.latest_profile.document.model_dump(mode="json"),
                    indent=2,
                    ensure_ascii=False,
                ),
            },
        )
    return timeline


@router.get("/{portfolio_id}/alerts", response_model=list[PortfolioAlertResponse])
async def get_portfolio_alerts(
    portfolio_id: str,
    alert_status: Literal["open", "acknowledged", "resolved"] | None = Query(default=None, alias="status"),
    route_label: str | None = Query(default=None, max_length=120),
    db: AsyncSession = Depends(get_db),
) -> list[PortfolioAlertResponse]:
    await _load_portfolio(portfolio_id, db)
    return await list_alerts(db, portfolio_id, status=alert_status, route_label=route_label)


@router.post("/{portfolio_id}/alerts/{alert_id}/acknowledge", response_model=PortfolioAlertResponse)
async def post_alert_acknowledge(
    portfolio_id: str,
    alert_id: str,
    request: AlertAcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
) -> PortfolioAlertResponse:
    await _load_portfolio(portfolio_id, db)
    try:
        alert = await acknowledge_alert(db, portfolio_id, alert_id, request)
        await db.commit()
        return alert_response(alert)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/{portfolio_id}/alerts/{alert_id}/resolve", response_model=PortfolioAlertResponse)
async def post_alert_resolve(
    portfolio_id: str,
    alert_id: str,
    request: AlertResolveRequest,
    db: AsyncSession = Depends(get_db),
) -> PortfolioAlertResponse:
    await _load_portfolio(portfolio_id, db)
    try:
        alert = await resolve_alert(db, portfolio_id, alert_id, request)
        await db.commit()
        return alert_response(alert)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/{portfolio_id}/control-plane/verify",
    response_model=ControlPlaneChainVerification,
)
async def get_control_plane_verification(
    portfolio_id: str,
    db: AsyncSession = Depends(get_db),
) -> ControlPlaneChainVerification:
    await _load_portfolio(portfolio_id, db)
    return await verify_control_plane_chains(db, portfolio_id)


@router.get("/{portfolio_id}/audit-events", response_model=list[PortfolioAuditEventResponse])
async def get_portfolio_audit_events(
    portfolio_id: str,
    limit: int = Query(default=200, ge=1, le=10000),
    db: AsyncSession = Depends(get_db),
) -> list[PortfolioAuditEventResponse]:
    await _load_portfolio(portfolio_id, db)
    return await list_audit_events(db, portfolio_id, limit=limit)


@router.get("/{portfolio_id}/control-plane/evidence", response_model=PortfolioControlPlaneEvidence)
async def get_control_plane_evidence(
    portfolio_id: str,
    db: AsyncSession = Depends(get_db),
):
    portfolio = await _load_portfolio(portfolio_id, db)
    bundle = await build_control_plane_evidence(db, portfolio)
    await db.commit()
    return JSONResponse(
        bundle.model_dump(mode="json"),
        headers={"Content-Disposition": f'attachment; filename="sentinel-control-plane-{portfolio_id}.json"'},
    )
