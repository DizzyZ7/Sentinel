from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.routers.comparison import router


async def test_comparison_endpoint_returns_json_and_html(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/comparison.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with factory() as session:
        baseline = Scan(
            id="baseline",
            status="completed",
            source_type="zip",
            original_filename="v1.zip",
            workspace_path=str(tmp_path / "baseline"),
            risk_score=30.0,
        )
        current = Scan(
            id="current",
            status="completed",
            source_type="zip",
            original_filename="v2.zip",
            workspace_path=str(tmp_path / "current"),
            risk_score=60.0,
        )
        baseline.findings.append(
            Finding(
                id="legacy",
                rule_id="PY_SQL_INTERPOLATION",
                title="SQL interpolation",
                file_path="app.py",
                line=4,
                end_line=4,
                language="python",
                snippet="db.execute(f'SELECT {user_id}')",
                static_rationale="Interpolated SQL",
                static_confidence=0.96,
                llm_status="completed",
                confirmed=True,
                severity="high",
                patch_valid=False,
            )
        )
        current.findings.extend(
            [
                Finding(
                    id="legacy-moved",
                    rule_id="PY_SQL_INTERPOLATION",
                    title="SQL interpolation",
                    file_path="app.py",
                    line=40,
                    end_line=40,
                    language="python",
                    snippet="db.execute(f'SELECT {user_id}')",
                    static_rationale="Interpolated SQL",
                    static_confidence=0.96,
                    llm_status="completed",
                    confirmed=True,
                    severity="high",
                    patch_valid=False,
                ),
                Finding(
                    id="introduced",
                    rule_id="PY_SSRF",
                    title="Outbound request",
                    file_path="client.py",
                    line=8,
                    end_line=8,
                    language="python",
                    snippet="requests.get(request.args['url'])",
                    static_rationale="Request URL reaches HTTP client",
                    static_confidence=0.9,
                    llm_status="completed",
                    confirmed=True,
                    severity="high",
                    patch_valid=False,
                ),
            ]
        )
        session.add_all([baseline, current])
        await session.commit()

    test_app = FastAPI()
    test_app.include_router(router)

    async def override_db():
        async with factory() as session:
            yield session

    test_app.dependency_overrides[get_db] = override_db
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as client:
        response = await client.get("/scan/current/compare/baseline")
        assert response.status_code == 200
        payload = response.json()
        assert payload["summary"]["persistent"] == 1
        assert payload["summary"]["introduced"] == 1
        assert payload["delta_gate"]["state"] == "blocked"

        html = await client.get("/scan/current/compare/baseline?format=html")
        assert html.status_code == 200
        assert "NO-NEW-RISK POLICY" in html.text
        assert "Outbound request" in html.text

    await engine.dispose()
