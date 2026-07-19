from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.routers.security_posture import router
from app.services.lineage import ensure_root_lineage
from app.services.project_context import ensure_project_context
from app.services.security_policy import ensure_security_policy
from app.services.security_sla import ensure_security_sla


async def build_app(tmp_path: Path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/posture-api.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-1",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "scan"),
        candidate_count=1,
        finding_count=1,
        created_at=now,
        completed_at=now,
    )
    scan.findings.append(
        Finding(
            id="finding-1",
            rule_id="PY_COMMAND_INJECTION",
            title="Command injection",
            file_path="app/jobs.py",
            line=4,
            end_line=4,
            language="python",
            snippet="os.system(command)",
            static_rationale="Request data reaches a shell.",
            static_confidence=0.98,
            llm_status="completed",
            confirmed=True,
            severity="high",
            confidence=0.98,
            patch_valid=False,
        )
    )
    async with factory() as session:
        session.add(scan)
        await session.flush()
        await ensure_root_lineage(session, scan)
        await ensure_project_context(session, scan)
        await ensure_security_policy(session, scan)
        await ensure_security_sla(session, scan)
        await session.commit()

    app = FastAPI()
    app.include_router(router)

    async def override_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    return app, engine


async def test_security_posture_json_and_html(tmp_path: Path) -> None:
    app, engine = await build_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/scan/scan-1/security-posture")
        assert response.status_code == 200
        payload = response.json()
        assert payload["schema_version"] == "sentinel-security-posture-v1"
        assert payload["summary"]["generations"] == 1
        assert payload["points"][0]["confirmed_findings"] == 1

        html = await client.get("/scan/scan-1/security-posture?format=html")
        assert html.status_code == 200
        assert "lineage posture and remediation effectiveness" in html.text
    await engine.dispose()


def test_main_openapi_contains_security_posture_contract() -> None:
    from app.main import app

    assert "get" in app.openapi()["paths"]["/scan/{scan_id}/security-posture"]
