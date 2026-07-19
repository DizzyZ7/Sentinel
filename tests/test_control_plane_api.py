from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.routers.control_plane import router as control_plane_router
from app.routers.portfolio import router as portfolio_router


async def build_app(tmp_path: Path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/control-api.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    app = FastAPI()
    app.include_router(portfolio_router)
    app.include_router(control_plane_router)

    async def override_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    return app, engine


async def test_control_plane_api_full_surface(tmp_path: Path) -> None:
    app, engine = await build_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post("/portfolios", json={"name": "Production"})
        assert created.status_code == 201
        portfolio_id = created.json()["portfolio_id"]

        control = await client.get(f"/portfolios/{portfolio_id}/control-plane")
        assert control.status_code == 200
        assert control.json()["latest_profile"]["version"] == 1

        updated = await client.put(
            f"/portfolios/{portfolio_id}/control-plane?actor=security-lead",
            json={"snapshot_interval_hours": 12, "route_labels": ["soc"]},
        )
        assert updated.status_code == 200
        assert updated.json()["latest_profile"]["version"] == 2

        captured = await client.post(
            f"/portfolios/{portfolio_id}/snapshots",
            json={"source": "api", "actor": "ci", "idempotency_key": "build-42"},
        )
        assert captured.status_code == 201
        body = captured.json()
        assert body["snapshot"]["sequence"] == 1
        assert body["snapshot"]["state"] == "insufficient_evidence"

        duplicate = await client.post(
            f"/portfolios/{portfolio_id}/snapshots",
            json={"source": "api", "actor": "ci", "idempotency_key": "build-42"},
        )
        assert duplicate.status_code == 200
        assert duplicate.json()["created"] is False
        assert duplicate.json()["snapshot"]["snapshot_id"] == body["snapshot"]["snapshot_id"]

        snapshots = await client.get(f"/portfolios/{portfolio_id}/snapshots")
        assert snapshots.status_code == 200
        assert len(snapshots.json()) == 1

        detail = await client.get(f"/portfolios/{portfolio_id}/snapshots/{body['snapshot']['snapshot_id']}")
        assert detail.status_code == 200
        assert detail.json()["dashboard_sha256"]

        timeline = await client.get(f"/portfolios/{portfolio_id}/timeline")
        assert timeline.status_code == 200
        assert timeline.json()["schema_version"] == "sentinel-control-plane-timeline-v1"

        html = await client.get(f"/portfolios/{portfolio_id}/timeline?format=html")
        assert html.status_code == 200
        assert "SENTINEL CONTINUOUS SECURITY CONTROL PLANE" in html.text

        alerts = await client.get(f"/portfolios/{portfolio_id}/alerts?status=open&route_label=soc")
        assert alerts.status_code == 200
        assert alerts.json()
        alert_id = alerts.json()[0]["alert_id"]

        acknowledged = await client.post(
            f"/portfolios/{portfolio_id}/alerts/{alert_id}/acknowledge",
            json={"actor": "analyst"},
        )
        assert acknowledged.status_code == 200
        assert acknowledged.json()["status"] == "acknowledged"

        resolved = await client.post(
            f"/portfolios/{portfolio_id}/alerts/{alert_id}/resolve",
            json={"actor": "analyst", "reason": "Triaged"},
        )
        assert resolved.status_code == 200
        assert resolved.json()["status"] == "resolved"

        events = await client.get(f"/portfolios/{portfolio_id}/audit-events")
        assert events.status_code == 200
        assert events.json()[0]["event_sha256"]

        verification = await client.get(f"/portfolios/{portfolio_id}/control-plane/verify")
        assert verification.status_code == 200
        assert verification.json()["snapshot_chain_valid"] is True
        assert verification.json()["audit_chain_valid"] is True

        evidence = await client.get(f"/portfolios/{portfolio_id}/control-plane/evidence")
        assert evidence.status_code == 200
        assert evidence.json()["bundle_type"] == "sentinel-control-plane-evidence"
        assert evidence.json()["integrity"]["payload_sha256"]
        assert "attachment" in evidence.headers["content-disposition"]
    await engine.dispose()


def test_main_openapi_contains_control_plane_contracts() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "get" in paths["/portfolios/{portfolio_id}/control-plane"]
    assert "post" in paths["/portfolios/{portfolio_id}/snapshots"]
    assert "get" in paths["/portfolios/{portfolio_id}/timeline"]
    assert "get" in paths["/portfolios/{portfolio_id}/alerts"]
    assert "get" in paths["/portfolios/{portfolio_id}/control-plane/verify"]
    assert "get" in paths["/portfolios/{portfolio_id}/control-plane/evidence"]
