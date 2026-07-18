from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import get_db
from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.routers.risk_exception import router
from app.services.lineage import ensure_root_lineage
from app.services.project_context import demo_project_context, ensure_project_context
from app.services.security_policy import demo_security_policy, ensure_security_policy


async def build_app(tmp_path: Path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/exception-api.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-1",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
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
        await session.commit()
    app = FastAPI()
    app.include_router(router)

    async def override_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    return app, engine


async def test_exception_api_lifecycle_json_html_and_audit(tmp_path: Path) -> None:
    app, engine = await build_app(tmp_path)
    transport = ASGITransport(app=app)
    future = datetime.now(UTC) + timedelta(days=30)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/scan/scan-1/risk-exceptions",
            json={
                "target_type": "finding",
                "target_value": "finding-1",
                "title": "Temporary legacy acceptance",
                "justification": (
                    "The endpoint is protected by a compensating control while "
                    "the replacement is completed."
                ),
                "risk_owner": "Payments owner",
                "requested_by": "developer@example.com",
                "maximum_severity": "high",
                "expires_at": future.isoformat(),
            },
        )
        assert created.status_code == 201
        exception_id = created.json()["id"]
        assert created.json()["status"] == "pending"
        assert created.json()["events"][0]["event_type"] == "requested"

        self_decision = await client.post(
            f"/scan/scan-1/risk-exceptions/{exception_id}/decision",
            json={
                "decision": "approved",
                "actor": "developer@example.com",
                "reason": "The requester should not be allowed to approve this exception.",
            },
        )
        assert self_decision.status_code == 409

        approved = await client.post(
            f"/scan/scan-1/risk-exceptions/{exception_id}/decision",
            json={
                "decision": "approved",
                "actor": "security@example.com",
                "reason": "The temporary controls and remediation deadline were independently reviewed.",
            },
        )
        assert approved.status_code == 200
        assert approved.json()["active"] is True
        assert [event["event_type"] for event in approved.json()["events"]] == [
            "requested",
            "approved",
        ]

        governance = await client.get("/scan/scan-1/exception-aware-compliance")
        assert governance.status_code == 200
        assert governance.json()["state"] == "accepted_risk"
        assert governance.json()["release_permitted"] is True

        register_html = await client.get("/scan/scan-1/risk-exceptions?format=html")
        assert register_html.status_code == 200
        assert "Temporary exceptions" in register_html.text
        governance_html = await client.get("/scan/scan-1/exception-aware-compliance?format=html")
        assert governance_html.status_code == 200
        assert "ACCEPTED_RISK" in governance_html.text

        revoked = await client.post(
            f"/scan/scan-1/risk-exceptions/{exception_id}/revoke",
            json={
                "actor": "security@example.com",
                "reason": "The documented compensating control is no longer available.",
            },
        )
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "revoked"
        blocked = await client.get("/scan/scan-1/exception-aware-compliance")
        assert blocked.json()["state"] == "blocked"

    await engine.dispose()


def test_main_openapi_contains_exception_contracts() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "post" in paths["/scan/{scan_id}/risk-exceptions"]
    assert "post" in paths["/scan/{scan_id}/risk-exceptions/{exception_id}/decision"]
    assert "post" in paths["/scan/{scan_id}/risk-exceptions/{exception_id}/revoke"]
    assert "get" in paths["/scan/{scan_id}/exception-aware-compliance"]
    assert "get" in paths["/scan/{current_scan_id}/exception-debt/compare/{baseline_scan_id}"]
