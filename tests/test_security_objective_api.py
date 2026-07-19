from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.routers.security_objective import router
from app.schemas.security_objective import SecurityObjectiveDocument
from app.services.lineage import ensure_root_lineage
from app.services.project_context import ensure_project_context
from app.services.security_objective import ensure_security_objective
from app.services.security_policy import ensure_security_policy
from app.services.security_sla import ensure_security_sla


async def build_app(tmp_path: Path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/objective-api.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
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
    objective = SecurityObjectiveDocument(target_date=now + timedelta(days=30))
    async with factory() as session:
        session.add(scan)
        await session.flush()
        await ensure_root_lineage(session, scan)
        await ensure_project_context(session, scan)
        await ensure_security_policy(session, scan)
        await ensure_security_sla(session, scan)
        await ensure_security_objective(session, scan, objective, source="declared")
        await session.commit()

    app = FastAPI()
    app.include_router(router)

    async def override_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    return app, engine, objective


async def test_security_objective_status_preview_report_and_html(tmp_path: Path) -> None:
    app, engine, objective = await build_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        status = await client.get("/scan/scan-1/security-objectives")
        assert status.status_code == 200
        assert status.json()["assigned_profile"]["version"] == 1

        preview_document = objective.model_copy(update={
            "max_posture_score": 100.0,
            "max_confirmed_findings": 2,
            "max_policy_blockers": 100,
            "max_overdue_findings": 100,
            "max_accepted_risk_findings": 100,
            "min_sla_attainment_rate": 0.0,
            "max_mean_resolution_hours": 10000.0,
            "max_recurrence_rate": 100.0,
            "require_release_gate_passed": False,
            "require_policy_passed": False,
            "require_governance_passed": False,
        })
        preview = await client.post(
            "/scan/scan-1/security-objectives/preview",
            json=preview_document.model_dump(mode="json"),
        )
        assert preview.status_code == 200
        assert preview.json()["report"]["evaluation"]["state"] == "met"

        report = await client.get("/scan/scan-1/objective-report")
        assert report.status_code == 200
        assert report.json()["schema_version"] == "sentinel-security-objective-report-v1"
        assert report.json()["forecast"]["status"] == "insufficient_history"

        html = await client.get("/scan/scan-1/objective-report?format=html")
        assert html.status_code == 200
        assert "Remediation capacity forecast" in html.text

        updated = objective.model_copy(update={"max_posture_score": 20.0})
        saved = await client.put(
            "/scan/scan-1/security-objectives",
            json=updated.model_dump(mode="json"),
        )
        assert saved.status_code == 200
        assert saved.json()["assigned_profile"]["version"] == 1
        assert saved.json()["latest_profile"]["version"] == 2
    await engine.dispose()


def test_main_openapi_contains_security_objective_contracts() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "get" in paths["/scan/{scan_id}/security-objectives"]
    assert "put" in paths["/scan/{scan_id}/security-objectives"]
    assert "post" in paths["/scan/{scan_id}/security-objectives/preview"]
    assert "get" in paths["/scan/{scan_id}/objective-report"]
