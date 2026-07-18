from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.routers.lineage import router
from app.services.lineage import ensure_root_lineage, link_rescan


def finding(identifier: str, snippet: str, rule_id: str = "PY_SQL_INTERPOLATION") -> Finding:
    return Finding(
        id=identifier,
        rule_id=rule_id,
        title="Security evidence",
        file_path="app.py",
        line=4,
        end_line=4,
        language="python",
        snippet=snippet,
        static_rationale="Test evidence",
        static_confidence=0.96,
        llm_status="completed",
        confirmed=True,
        severity="high",
        patch_valid=False,
    )


async def build_app(tmp_path: Path, introduced: bool) -> tuple[FastAPI, object]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/ci.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    now = datetime.now(UTC)
    baseline = Scan(
        id="baseline",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(tmp_path / "baseline"),
        created_at=now,
        completed_at=now,
        risk_score=40.0,
    )
    current = Scan(
        id="current",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(tmp_path / "current"),
        created_at=now + timedelta(minutes=1),
        completed_at=now + timedelta(minutes=1),
        risk_score=60.0 if introduced else 40.0,
    )
    baseline.findings.append(finding("baseline-finding", "db.execute(f'SELECT {user_id}')"))
    current.findings.append(finding("current-persistent", "db.execute(f'SELECT {user_id}')"))
    if introduced:
        current.findings.append(finding("current-new", "requests.get(request.args['url'])", "PY_SSRF"))

    async with factory() as session:
        session.add(baseline)
        await session.flush()
        await ensure_root_lineage(session, baseline)
        session.add(current)
        await session.flush()
        await link_rescan(session, baseline, current)
        await session.commit()

    test_app = FastAPI()
    test_app.include_router(router)

    async def override_db():
        async with factory() as session:
            yield session

    test_app.dependency_overrides[get_db] = override_db
    return test_app, engine


async def test_ci_gate_uses_parent_baseline_and_returns_security_exit_code(tmp_path: Path) -> None:
    app, engine = await build_app(tmp_path, introduced=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/scan/current/ci-gate")
        assert response.status_code == 409
        assert response.headers["X-Sentinel-Exit-Code"] == "1"
        payload = response.json()
        assert payload["baseline_scan_id"] == "baseline"
        assert payload["exit_code"] == 1
        assert payload["summary"]["introduced"] == 1

        lineage = await client.get("/scan/current/lineage")
        assert lineage.status_code == 200
        assert lineage.json()["default_baseline_scan_id"] == "baseline"
    await engine.dispose()


async def test_ci_gate_passes_when_only_persistent_evidence_remains(tmp_path: Path) -> None:
    app, engine = await build_app(tmp_path, introduced=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/scan/current/ci-gate")
        assert response.status_code == 200
        assert response.headers["X-Sentinel-Exit-Code"] == "0"
        assert response.json()["exit_code"] == 0
        assert response.json()["summary"]["persistent"] == 1
    await engine.dispose()
