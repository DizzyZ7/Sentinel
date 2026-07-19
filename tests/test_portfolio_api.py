from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.scan import Scan
from app.routers.portfolio import router
from app.services.lineage import ensure_root_lineage
from app.services.project_context import ensure_project_context
from app.services.security_objective import ensure_security_objective
from app.services.security_policy import ensure_security_policy
from app.services.security_sla import ensure_security_sla


async def build_app(tmp_path: Path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/portfolio-api.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
    scan = Scan(
        id="root-1",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "root"),
        created_at=now,
        completed_at=now,
    )
    async with factory() as session:
        session.add(scan)
        await session.flush()
        await ensure_root_lineage(session, scan)
        await ensure_project_context(session, scan)
        await ensure_security_policy(session, scan)
        await ensure_security_sla(session, scan)
        await ensure_security_objective(session, scan)
        await session.commit()
    app = FastAPI()
    app.include_router(router)

    async def override_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    return app, engine


async def test_portfolio_api_full_surface(tmp_path: Path) -> None:
    app, engine = await build_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post(
            "/portfolios",
            json={
                "name": "Production",
                "description": "Executive scope",
                "governance": {"max_scan_age_days": 365},
                "members": [
                    {
                        "root_scan_id": "root-1",
                        "display_name": "Core API",
                        "business_unit": "Platform",
                        "criticality": "critical",
                    }
                ],
            },
        )
        assert created.status_code == 201
        portfolio_id = created.json()["portfolio_id"]

        listed = await client.get("/portfolios")
        assert listed.status_code == 200
        assert listed.json()[0]["portfolio_id"] == portfolio_id

        dashboard = await client.get(f"/portfolios/{portfolio_id}/dashboard")
        assert dashboard.status_code == 200
        assert dashboard.json()["schema_version"] == "sentinel-portfolio-dashboard-v1"
        assert dashboard.json()["summary"]["total_members"] == 1

        html = await client.get(f"/portfolios/{portfolio_id}/dashboard?format=html")
        assert html.status_code == 200
        assert "SENTINEL PORTFOLIO GOVERNANCE" in html.text

        governance = await client.put(
            f"/portfolios/{portfolio_id}/governance",
            json={"max_scan_age_days": 365, "max_blocked_members": 1},
        )
        assert governance.status_code == 200
        assert governance.json()["latest_profile"]["version"] == 2

        evidence = await client.get(f"/portfolios/{portfolio_id}/evidence")
        assert evidence.status_code == 200
        assert evidence.json()["bundle_type"] == "sentinel-portfolio-evidence"
        assert evidence.json()["integrity"]["payload_sha256"]
        assert "attachment" in evidence.headers["content-disposition"]

        removed = await client.delete(f"/portfolios/{portfolio_id}/members/root-1")
        assert removed.status_code == 204
        empty = await client.get(f"/portfolios/{portfolio_id}/dashboard")
        assert empty.json()["summary"]["state"] == "insufficient_evidence"
    await engine.dispose()


def test_main_openapi_contains_portfolio_contracts() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "get" in paths["/portfolios"]
    assert "post" in paths["/portfolios"]
    assert "post" in paths["/portfolios/{portfolio_id}/members"]
    assert "get" in paths["/portfolios/{portfolio_id}/dashboard"]
    assert "get" in paths["/portfolios/{portfolio_id}/evidence"]
