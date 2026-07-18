from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.routers.security_policy import router
from app.services.lineage import ensure_root_lineage
from app.services.project_context import demo_project_context, ensure_project_context
from app.services.security_policy import ensure_security_policy


async def build_app(tmp_path: Path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/policy-api.db")
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
    )
    scan.findings.append(
        Finding(
            id="finding-1",
            rule_id="PY_SQL_INTERPOLATION",
            title="SQL injection",
            file_path="confirmed_sql.py",
            line=8,
            end_line=8,
            language="python",
            snippet="cursor.execute(query)",
            static_rationale="Input reaches SQL.",
            static_confidence=0.97,
            llm_status="completed",
            confirmed=True,
            severity="medium",
            confidence=0.98,
            patch_valid=False,
        )
    )
    async with factory() as session:
        session.add(scan)
        await session.flush()
        await ensure_root_lineage(session, scan)
        await ensure_project_context(session, scan, demo_project_context(), source="built_in")
        await ensure_security_policy(session, scan)
        await session.commit()
    app = FastAPI()
    app.include_router(router)
    async def override_db():
        async with factory() as session:
            yield session
    app.dependency_overrides[get_db] = override_db
    return app, engine


async def test_policy_history_preview_compliance_and_html(tmp_path: Path) -> None:
    app, engine = await build_app(tmp_path)
    document = {
        "policy_name": "Strict production policy",
        "base_block_on": "high",
        "public_asset_block_on": "medium",
        "restricted_data_block_on": "medium",
        "critical_asset_block_on": "medium",
        "require_valid_patch_from": "medium",
        "require_passed_proof_from": "medium",
        "require_human_approval_from": "medium",
        "frameworks": ["SOC 2"],
        "overrides": [],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        initial = await client.get("/scan/scan-1/security-policy")
        assert initial.status_code == 200
        assert initial.json()["assigned_profile"]["version"] == 1

        preview = await client.post("/scan/scan-1/security-policy/preview", json=document)
        assert preview.status_code == 200
        assert preview.json()["compliance"]["state"] == "blocked"
        assert preview.json()["compliance"]["summary"]["blocking_findings"] == 1

        saved = await client.put("/scan/scan-1/security-policy", json=document)
        assert saved.status_code == 200
        assert saved.json()["assigned_profile"]["version"] == 1
        assert saved.json()["latest_profile"]["version"] == 2

        compliance = await client.get("/scan/scan-1/policy-compliance")
        assert compliance.status_code == 200
        assert compliance.json()["policy_version"] == 1

        html = await client.get("/scan/scan-1/security-policy?format=html")
        assert html.status_code == 200
        assert "Version the rules" in html.text
        report = await client.get("/scan/scan-1/policy-compliance?format=html")
        assert report.status_code == 200
        assert "ORGANIZATIONAL POLICY COMPLIANCE" in report.text
    await engine.dispose()


def test_security_policy_openapi_contract() -> None:
    app = FastAPI()
    app.include_router(router)
    paths = app.openapi()["paths"]
    assert set(paths["/scan/{scan_id}/security-policy"]) >= {"get", "put"}
    assert "/scan/{scan_id}/security-policy/preview" in paths
    assert "/scan/{scan_id}/policy-compliance" in paths
    assert "/scan/{current_scan_id}/policy-compliance/compare/{baseline_scan_id}" in paths
