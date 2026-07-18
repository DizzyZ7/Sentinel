from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.project_context import ProjectAssetContext, ProjectContextDocument
from app.schemas.security_sla import SecuritySLADocument, SecuritySLAOverride
from app.services.lineage import ensure_root_lineage, link_rescan
from app.services.project_context import ensure_project_context, load_context_snapshot
from app.services.security_sla import (
    assign_latest_security_sla,
    build_security_debt_dashboard,
    build_security_sla_status,
    compare_security_debt,
    create_security_sla_version,
    ensure_security_sla,
    load_sla_snapshot,
    persist_finding_slas,
    sla_sha256,
)


def make_finding(finding_id: str, *, line: int = 8, snippet: str = "cursor.execute(query)") -> Finding:
    return Finding(
        id=finding_id,
        rule_id="PY_SQL_INTERPOLATION",
        title="SQL injection",
        file_path="app/payments/query.py",
        line=line,
        end_line=line,
        language="python",
        snippet=snippet,
        static_rationale="Input reaches SQL.",
        static_confidence=0.97,
        llm_status="completed",
        confirmed=True,
        severity="high",
        confidence=0.98,
        patch_valid=False,
    )


def context_document() -> ProjectContextDocument:
    return ProjectContextDocument(
        project_name="Payments",
        environment="production",
        internet_exposed=True,
        assets=[
            ProjectAssetContext(
                asset_id="payments-api",
                name="Payments API",
                path_patterns=["app/payments/**"],
                criticality="critical",
                exposure="public",
                data_classification="restricted",
                owner="Payments Platform",
            )
        ],
    )


def sla_document(hours: int = 48) -> SecuritySLADocument:
    return SecuritySLADocument(
        profile_name="Payments SLA",
        critical_hours=12,
        high_hours=48,
        medium_hours=240,
        low_hours=720,
        production_multiplier=1.0,
        public_asset_multiplier=1.0,
        restricted_data_multiplier=1.0,
        critical_asset_multiplier=1.0,
        at_risk_window_hours=12,
        default_team="AppSec",
        default_risk_owner="Security Lead",
        overrides=[
            SecuritySLAOverride(
                override_id="payments-owner",
                name="Payments ownership",
                asset_ids=["payments-api"],
                due_hours=hours,
                assigned_team="Payments Platform",
                risk_owner="Payments Director",
                escalation_contact="payments-security@example.invalid",
            )
        ],
    )


async def test_sla_versions_and_finding_clock_survive_rescan(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/sla.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    started = datetime(2026, 7, 1, 8, 0, tzinfo=UTC)
    baseline = Scan(
        id="baseline",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "baseline"),
        created_at=started,
        completed_at=started + timedelta(minutes=5),
    )
    baseline.findings.append(make_finding("finding-base", line=8))
    current = Scan(
        id="current",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "current"),
        created_at=started + timedelta(hours=30),
        completed_at=started + timedelta(hours=30, minutes=5),
    )
    current.findings.append(make_finding("finding-current", line=44))

    async with factory() as session:
        session.add(baseline)
        await session.flush()
        await ensure_root_lineage(session, baseline)
        await ensure_project_context(session, baseline, context_document(), source="declared")
        first = await ensure_security_sla(session, baseline, sla_document(), source="declared")
        await persist_finding_slas(session, baseline, await load_context_snapshot(session, baseline.id))
        await create_security_sla_version(session, baseline, sla_document(hours=96))
        session.add(current)
        await session.flush()
        await link_rescan(session, baseline, current)
        await assign_latest_security_sla(session, baseline, current)
        await persist_finding_slas(session, current, await load_context_snapshot(session, baseline.id))
        await session.commit()

        baseline_dashboard = await build_security_debt_dashboard(
            session, baseline, at=started + timedelta(hours=10)
        )
        current_dashboard = await build_security_debt_dashboard(
            session, current, at=started + timedelta(hours=50)
        )
        root_snapshot = await load_sla_snapshot(session, baseline.id)
        child_snapshot = await load_sla_snapshot(session, current.id)
        status = await build_security_sla_status(session, baseline)

    before = baseline_dashboard.findings[0]
    after = current_dashboard.findings[0]
    assert first.version == 1
    assert root_snapshot and root_snapshot.version == 1
    assert child_snapshot and child_snapshot.version == 2
    assert status.latest_profile.version == 2
    assert before.assigned_team == "Payments Platform"
    assert after.assignment_source == "lineage_inherited"
    assert after.started_at == before.started_at
    assert after.due_at == before.due_at
    assert after.profile_version == 1
    assert after.state == "overdue"
    await engine.dispose()


async def test_dashboard_tracks_fail_closed_unreviewed_evidence_and_comparison(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/debt.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime(2026, 7, 1, 8, 0, tzinfo=UTC)
    baseline = Scan(id="b", status="completed", source_type="zip", workspace_path="/tmp/b", created_at=now)
    baseline.findings.append(
        Finding(
            id="unreviewed",
            rule_id="PY_COMMAND_INJECTION",
            title="Command execution candidate",
            file_path="app/jobs/run.py",
            line=3,
            end_line=3,
            language="python",
            snippet="os.system(command)",
            static_rationale="Input reaches shell.",
            static_confidence=0.96,
            llm_status="skipped",
            confirmed=None,
        )
    )
    current = Scan(
        id="c",
        status="completed",
        source_type="zip",
        workspace_path="/tmp/c",
        created_at=now + timedelta(hours=2),
    )
    current.findings.append(make_finding("new-sql"))
    current.findings.append(Finding(
        id="unreviewed-current",
        rule_id="PY_COMMAND_INJECTION",
        title="Command execution candidate",
        file_path="app/jobs/run.py",
        line=30,
        end_line=30,
        language="python",
        snippet="os.system(command)",
        static_rationale="Input reaches shell.",
        static_confidence=0.96,
        llm_status="skipped",
        confirmed=None,
    ))
    async with factory() as session:
        session.add(baseline)
        await session.flush()
        await ensure_root_lineage(session, baseline)
        await ensure_project_context(session, baseline)
        await ensure_security_sla(session, baseline, sla_document(), source="declared")
        await persist_finding_slas(session, baseline, await load_context_snapshot(session, baseline.id))
        session.add(current)
        await session.flush()
        await link_rescan(session, baseline, current)
        await assign_latest_security_sla(session, baseline, current)
        await persist_finding_slas(session, current, await load_context_snapshot(session, baseline.id))
        before = await build_security_debt_dashboard(session, baseline, at=now + timedelta(hours=3))
        after = await build_security_debt_dashboard(session, current, at=now + timedelta(hours=3))
        comparison = compare_security_debt(before, after)
    assert before.findings[0].severity == "high"
    assert comparison.summary.introduced == 1
    assert comparison.summary.persistent == 1
    assert comparison.summary.resolved == 0
    await engine.dispose()


def test_sla_document_hash_and_validation() -> None:
    document = sla_document()
    assert sla_sha256(document) == sla_sha256(SecuritySLADocument.model_validate(document.model_dump()))
    with pytest.raises(ValidationError):
        SecuritySLADocument(critical_hours=100, high_hours=10)
    with pytest.raises(ValidationError):
        SecuritySLAOverride(override_id="unsafe", name="Unsafe", path_patterns=["../secret/**"])
