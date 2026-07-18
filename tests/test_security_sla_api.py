from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.routers.risk_exception import router as exception_router
from app.routers.security_sla import router as sla_router
from app.services.lineage import ensure_root_lineage
from app.services.project_context import demo_project_context, ensure_project_context
from app.services.security_policy import demo_security_policy, ensure_security_policy
from app.services.security_sla import ensure_security_sla


async def build_app(tmp_path: Path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/sla-api.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-1",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "scan"),
        created_at=now,
        completed_at=now,
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
            severity="high",
            confidence=0.98,
            patch_valid=False,
        )
    )
    async with factory() as session:
        session.add(scan)
        await session.flush()
        await ensure_root_lineage(session, scan)
        await ensure_project_context(session, scan, demo_project_context(), source="built_in")
        await ensure_security_policy(session, scan, demo_security_policy(), source="built_in")
        await ensure_security_sla(
            session,
            scan,
            document=None,
            source="inferred",
        )
        await session.commit()
    app = FastAPI()
    app.include_router(sla_router)
    app.include_router(exception_router)

    async def override_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    return app, engine, now


async def test_sla_api_preview_debt_exception_deadline_and_renewal(tmp_path: Path) -> None:
    app, engine, now = await build_app(tmp_path)
    document = {
        "profile_name": "Strict production SLA",
        "critical_hours": 4,
        "high_hours": 24,
        "medium_hours": 120,
        "low_hours": 360,
        "production_multiplier": 1.0,
        "public_asset_multiplier": 1.0,
        "restricted_data_multiplier": 1.0,
        "critical_asset_multiplier": 1.0,
        "at_risk_window_hours": 6,
        "default_team": "AppSec",
        "default_risk_owner": "Security Lead",
        "overrides": [],
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        initial = await client.get("/scan/scan-1/security-sla")
        assert initial.status_code == 200
        assert initial.json()["assigned_profile"]["version"] == 1

        preview = await client.post("/scan/scan-1/security-sla/preview", json=document)
        assert preview.status_code == 200
        assert preview.json()["dashboard"]["summary"]["total"] == 1

        saved = await client.put("/scan/scan-1/security-sla", json=document)
        assert saved.status_code == 200
        assert saved.json()["assigned_profile"]["version"] == 1
        assert saved.json()["latest_profile"]["version"] == 2

        debt = await client.get("/scan/scan-1/security-debt")
        assert debt.status_code == 200
        due_at = datetime.fromisoformat(debt.json()["findings"][0]["due_at"])
        assert debt.json()["findings"][0]["assigned_team"]
        html = await client.get("/scan/scan-1/security-debt?format=html")
        assert "ownership and remediation clocks" in html.text

        too_long = await client.post(
            "/scan/scan-1/risk-exceptions",
            json={
                "target_type": "finding",
                "target_value": "finding-1",
                "title": "Too long acceptance",
                "justification": "This request intentionally exceeds the immutable remediation deadline.",
                "risk_owner": "Security Lead",
                "requested_by": "developer@example.com",
                "maximum_severity": "high",
                "expires_at": (due_at + timedelta(hours=1)).isoformat(),
            },
        )
        assert too_long.status_code == 422
        assert "SLA deadline" in too_long.json()["detail"]

        created = await client.post(
            "/scan/scan-1/risk-exceptions",
            json={
                "target_type": "finding",
                "target_value": "finding-1",
                "title": "Short compensating control",
                "justification": "A temporary compensating control is active while remediation is completed.",
                "risk_owner": "Security Lead",
                "requested_by": "developer@example.com",
                "maximum_severity": "high",
                "expires_at": (now + timedelta(hours=6)).isoformat(),
            },
        )
        assert created.status_code == 201
        exception_id = created.json()["id"]
        approved = await client.post(
            f"/scan/scan-1/risk-exceptions/{exception_id}/decision",
            json={
                "decision": "approved",
                "actor": "security@example.com",
                "reason": "The compensating control and deadline were independently verified.",
            },
        )
        assert approved.status_code == 200

        renewal = await client.post(
            f"/scan/scan-1/risk-exceptions/{exception_id}/renew",
            json={
                "actor": "owner@example.com",
                "reason": "Request a short successor window while the final deployment completes.",
                "expires_at": (now + timedelta(hours=12)).isoformat(),
            },
        )
        assert renewal.status_code == 201
        assert renewal.json()["status"] == "pending"
        assert renewal.json()["events"][0]["metadata"]["renews_exception_id"] == exception_id

        rejected_renewal = await client.post(
            f"/scan/scan-1/risk-exceptions/{exception_id}/renew",
            json={
                "actor": "owner@example.com",
                "reason": "This successor intentionally exceeds the remediation SLA boundary.",
                "expires_at": (due_at + timedelta(hours=2)).isoformat(),
            },
        )
        assert rejected_renewal.status_code == 409
        assert "SLA deadline" in rejected_renewal.json()["detail"]
    await engine.dispose()


def test_main_openapi_contains_sla_contracts() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert set(paths["/scan/{scan_id}/security-sla"]) >= {"get", "put"}
    assert "post" in paths["/scan/{scan_id}/security-sla/preview"]
    assert "get" in paths["/scan/{scan_id}/security-debt"]
    assert "get" in paths["/scan/{current_scan_id}/security-debt/compare/{baseline_scan_id}"]
    assert "post" in paths["/scan/{scan_id}/risk-exceptions/{exception_id}/renew"]
