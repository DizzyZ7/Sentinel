from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.routers.project_context import router
from app.services.lineage import ensure_root_lineage
from app.services.project_context import ensure_project_context
from app.services.risk_intelligence import ensure_risk_intelligence


async def build_app(tmp_path: Path) -> tuple[FastAPI, object]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/context-api.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    scan = Scan(
        id="scan-1",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(tmp_path / "scan"),
        created_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        risk_score=20.0,
    )
    finding = Finding(
        id="finding-1",
        rule_id="PY_SSRF",
        title="Server-side request forgery",
        file_path="app/integrations/fetch.py",
        line=9,
        end_line=9,
        language="python",
        snippet="requests.get(url)",
        static_rationale="Input reaches outbound request.",
        static_confidence=0.96,
        llm_status="completed",
        confirmed=True,
        severity="high",
        confidence=0.98,
        patch_valid=False,
    )
    scan.findings.append(finding)
    ensure_risk_intelligence(finding)
    async with factory() as session:
        session.add(scan)
        await session.flush()
        await ensure_root_lineage(session, scan)
        await ensure_project_context(session, scan)
        await session.commit()

    app = FastAPI()
    app.include_router(router)

    async def override_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    return app, engine


async def test_project_context_history_preview_and_html(tmp_path: Path) -> None:
    app, engine = await build_app(tmp_path)
    document = {
        "project_name": "Integration gateway",
        "environment": "production",
        "internet_exposed": True,
        "default_criticality": "high",
        "default_exposure": "public",
        "default_data_classification": "confidential",
        "compliance_frameworks": ["SOC 2"],
        "assets": [
            {
                "asset_id": "outbound-gateway",
                "name": "Outbound integration gateway",
                "asset_type": "network_service",
                "path_patterns": ["app/integrations/**"],
                "criticality": "critical",
                "exposure": "public",
                "data_classification": "restricted",
                "data_types": ["service credentials"],
            }
        ],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        initial = await client.get("/scan/scan-1/project-context")
        assert initial.status_code == 200
        assert initial.json()["assigned_profile"]["version"] == 1
        assert initial.json()["assigned_profile"]["source"] == "inferred"

        preview = await client.post("/scan/scan-1/project-context/preview", json=document)
        assert preview.status_code == 200
        assert preview.json()["report"]["context"]["matched_assets"] == 1
        assert preview.json()["report"]["risks"][0]["risk"]["context_asset_id"] == "outbound-gateway"

        saved = await client.put("/scan/scan-1/project-context", json=document)
        assert saved.status_code == 200
        assert saved.json()["assigned_profile"]["version"] == 1
        assert saved.json()["latest_profile"]["version"] == 2
        assert saved.json()["next_rescan_uses_version"] == 2

        html = await client.get("/scan/scan-1/project-context?format=html")
        assert html.status_code == 200
        assert "Make business risk match the real system" in html.text
        assert "Save new version" in html.text
    await engine.dispose()


def test_project_context_openapi_contract() -> None:
    app = FastAPI()
    app.include_router(router)
    paths = app.openapi()["paths"]
    assert "/scan/{scan_id}/project-context" in paths
    assert set(paths["/scan/{scan_id}/project-context"]) >= {"get", "put"}
    assert "/scan/{scan_id}/project-context/preview" in paths
