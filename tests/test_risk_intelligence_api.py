from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.routers.risk_intelligence import router
from app.services.risk_intelligence import ensure_risk_intelligence


async def build_app(tmp_path: Path) -> tuple[FastAPI, object]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/risk.db")
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
        risk_score=15.0,
    )
    finding = Finding(
        id="finding-1",
        rule_id="PY_SSRF",
        title="Server-side request forgery",
        file_path="app/api/fetch.py",
        line=9,
        end_line=9,
        language="python",
        snippet="requests.get(request.args['url'])",
        static_rationale="Request URL reaches outbound client.",
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
        await session.commit()

    app = FastAPI()
    app.include_router(router)

    async def override_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    return app, engine


async def test_risk_intelligence_and_executive_report_endpoints(tmp_path: Path) -> None:
    app, engine = await build_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        risks = await client.get("/scan/scan-1/risk-intelligence")
        assert risks.status_code == 200
        assert risks.json()[0]["attack_surface"] == "network"
        assert risks.json()[0]["data_exposure"] == "internal services and cloud metadata"

        finding = await client.get("/scan/scan-1/findings/finding-1/risk-intelligence")
        assert finding.status_code == 200
        assert finding.json()["priority"] in {"immediate", "before_release"}

        report = await client.get("/scan/scan-1/executive-report")
        assert report.status_code == 200
        assert report.json()["summary"]["confirmed_findings"] == 1
        assert report.json()["summary"]["top_attack_surface"] == "network"

        html = await client.get("/scan/scan-1/executive-report?format=html")
        assert html.status_code == 200
        assert "Executive security decision" in html.text
        assert "Highest residual business risk" in html.text
    await engine.dispose()
