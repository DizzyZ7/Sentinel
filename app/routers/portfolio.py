import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.portfolio import SecurityPortfolio
from app.schemas.portfolio import (
    PortfolioCreate,
    PortfolioDashboard,
    PortfolioEvidenceBundle,
    PortfolioGovernanceDocument,
    PortfolioGovernanceStatus,
    PortfolioMemberInput,
    PortfolioMemberResponse,
    PortfolioResponse,
    PortfolioUpdate,
)
from app.services.portfolio import (
    build_portfolio_dashboard,
    build_portfolio_evidence,
    create_governance_version,
    create_portfolio,
    governance_status,
    list_portfolios,
    portfolio_response,
    remove_portfolio_member,
    update_portfolio,
    upsert_portfolio_member,
)

router = APIRouter(prefix="/portfolios", tags=["portfolio-governance"])
templates = Jinja2Templates(directory="app/templates")


async def _load_portfolio(portfolio_id: str, db: AsyncSession) -> SecurityPortfolio:
    portfolio = await db.get(SecurityPortfolio, portfolio_id)
    if portfolio is None:
        raise HTTPException(status_code=404, detail="Portfolio not found")
    return portfolio


@router.get("", response_model=None)
async def get_portfolios(
    request: Request,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    portfolios = await list_portfolios(db)
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="portfolios.html",
            context={"portfolios": portfolios},
        )
    return portfolios


@router.post("", response_model=PortfolioResponse, status_code=status.HTTP_201_CREATED)
async def post_portfolio(
    request: PortfolioCreate,
    db: AsyncSession = Depends(get_db),
) -> PortfolioResponse:
    try:
        portfolio = await create_portfolio(db, request)
        await db.commit()
        await db.refresh(portfolio)
        return await portfolio_response(db, portfolio)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{portfolio_id}", response_model=PortfolioResponse)
async def get_portfolio(
    portfolio_id: str,
    db: AsyncSession = Depends(get_db),
) -> PortfolioResponse:
    return await portfolio_response(db, await _load_portfolio(portfolio_id, db))


@router.put("/{portfolio_id}", response_model=PortfolioResponse)
async def put_portfolio(
    portfolio_id: str,
    request: PortfolioUpdate,
    db: AsyncSession = Depends(get_db),
) -> PortfolioResponse:
    portfolio = await update_portfolio(db, await _load_portfolio(portfolio_id, db), request)
    await db.commit()
    await db.refresh(portfolio)
    return await portfolio_response(db, portfolio)


@router.post("/{portfolio_id}/members", response_model=PortfolioMemberResponse)
async def post_portfolio_member(
    portfolio_id: str,
    request: PortfolioMemberInput,
    db: AsyncSession = Depends(get_db),
) -> PortfolioMemberResponse:
    portfolio = await _load_portfolio(portfolio_id, db)
    try:
        member = await upsert_portfolio_member(db, portfolio, request)
        await db.commit()
        await db.refresh(member)
        return PortfolioMemberResponse.model_validate(member, from_attributes=True)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete("/{portfolio_id}/members/{root_scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_portfolio_member(
    portfolio_id: str,
    root_scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    await _load_portfolio(portfolio_id, db)
    removed = await remove_portfolio_member(db, portfolio_id, root_scan_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Portfolio member not found")
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{portfolio_id}/governance", response_model=PortfolioGovernanceStatus)
async def get_portfolio_governance(
    portfolio_id: str,
    db: AsyncSession = Depends(get_db),
) -> PortfolioGovernanceStatus:
    await _load_portfolio(portfolio_id, db)
    try:
        return await governance_status(db, portfolio_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.put("/{portfolio_id}/governance", response_model=PortfolioGovernanceStatus)
async def put_portfolio_governance(
    portfolio_id: str,
    document: PortfolioGovernanceDocument,
    db: AsyncSession = Depends(get_db),
) -> PortfolioGovernanceStatus:
    portfolio = await _load_portfolio(portfolio_id, db)
    await create_governance_version(db, portfolio, document)
    await db.commit()
    return await governance_status(db, portfolio_id)


@router.get("/{portfolio_id}/dashboard", response_model=None)
async def get_portfolio_dashboard(
    request: Request,
    portfolio_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    portfolio = await _load_portfolio(portfolio_id, db)
    dashboard = await build_portfolio_dashboard(db, portfolio)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="portfolio_dashboard.html",
            context={
                "dashboard": dashboard,
                "governance_json": json.dumps(
                    dashboard.governance.document.model_dump(mode="json"), indent=2, ensure_ascii=False
                ),
            },
        )
    return PortfolioDashboard.model_validate(dashboard)


@router.get("/{portfolio_id}/evidence", response_model=PortfolioEvidenceBundle)
async def get_portfolio_evidence(
    portfolio_id: str,
    db: AsyncSession = Depends(get_db),
):
    portfolio = await _load_portfolio(portfolio_id, db)
    dashboard = await build_portfolio_dashboard(db, portfolio)
    await db.commit()
    bundle = build_portfolio_evidence(dashboard)
    return JSONResponse(
        bundle.model_dump(mode="json"),
        headers={"Content-Disposition": f'attachment; filename="sentinel-portfolio-{portfolio_id}.json"'},
    )
