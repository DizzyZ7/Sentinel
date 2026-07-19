from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.portfolio import PortfolioCreate, PortfolioGovernanceDocument, PortfolioMemberInput
from app.services.lineage import ensure_root_lineage, link_rescan
from app.services.portfolio import (
    build_portfolio_dashboard,
    build_portfolio_evidence,
    create_governance_version,
    create_portfolio,
    governance_status,
    upsert_portfolio_member,
)
from app.services.project_context import assign_latest_project_context, ensure_project_context
from app.services.security_objective import assign_latest_security_objective, ensure_security_objective
from app.services.security_policy import assign_latest_security_policy, ensure_security_policy
from app.services.security_sla import assign_latest_security_sla, ensure_security_sla


def risky_finding(finding_id: str, path: str) -> Finding:
    return Finding(
        id=finding_id,
        rule_id="PY_COMMAND_INJECTION",
        title="Command injection",
        file_path=path,
        line=8,
        end_line=8,
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


async def prepare_root(session: AsyncSession, scan: Scan) -> None:
    session.add(scan)
    await session.flush()
    await ensure_root_lineage(session, scan)
    await ensure_project_context(session, scan)
    await ensure_security_policy(session, scan)
    await ensure_security_sla(session, scan)
    await ensure_security_objective(session, scan)


async def prepare_rescan(session: AsyncSession, baseline: Scan, current: Scan) -> None:
    session.add(current)
    await session.flush()
    await link_rescan(session, baseline, current)
    await assign_latest_project_context(session, baseline, current)
    await assign_latest_security_policy(session, baseline, current)
    await assign_latest_security_sla(session, baseline, current)
    await assign_latest_security_objective(session, baseline, current)


async def test_portfolio_rolls_up_criticality_risk_and_blocks_exposure(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/portfolio.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
    clean = Scan(
        id="clean-root",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "clean"),
        created_at=now,
        completed_at=now,
    )
    risky = Scan(
        id="risky-root",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "risky"),
        candidate_count=1,
        finding_count=1,
        created_at=now,
        completed_at=now,
    )
    risky.findings.append(risky_finding("risk-1", "app/jobs.py"))
    async with factory() as session:
        await prepare_root(session, clean)
        await prepare_root(session, risky)
        portfolio = await create_portfolio(
            session,
            PortfolioCreate(
                name="Production",
                governance=PortfolioGovernanceDocument(
                    max_scan_age_days=365,
                    max_weighted_posture_score=100,
                    max_accepted_risk_findings=100,
                ),
                members=[
                    PortfolioMemberInput(
                        root_scan_id=clean.id,
                        display_name="Documentation",
                        criticality="low",
                    ),
                    PortfolioMemberInput(
                        root_scan_id=risky.id,
                        display_name="Payments",
                        criticality="critical",
                    ),
                ],
            ),
        )
        await session.commit()
        dashboard = await build_portfolio_dashboard(session, portfolio, generated_at=now + timedelta(days=1))
    assert dashboard.summary.state == "blocked"
    assert dashboard.summary.total_members == 2
    assert dashboard.summary.blocked_members == 1
    assert dashboard.summary.confirmed_findings == 1
    assert dashboard.summary.weighted_posture_score is not None
    assert dashboard.concentrations[0].display_name == "Payments"
    assert dashboard.concentrations[0].share_percent == 100.0
    await engine.dispose()


async def test_portfolio_fails_closed_on_ambiguous_heads_until_pinned(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/branches.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
    root = Scan(
        id="branch-root",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "root"),
        created_at=now,
        completed_at=now,
    )
    left = Scan(
        id="left",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "left"),
        created_at=now + timedelta(days=1),
        completed_at=now + timedelta(days=1),
    )
    right = Scan(
        id="right",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "right"),
        created_at=now + timedelta(days=2),
        completed_at=now + timedelta(days=2),
    )
    async with factory() as session:
        await prepare_root(session, root)
        await prepare_rescan(session, root, left)
        await prepare_rescan(session, root, right)
        portfolio = await create_portfolio(
            session,
            PortfolioCreate(
                name="Branched systems",
                governance=PortfolioGovernanceDocument(max_scan_age_days=365),
                members=[PortfolioMemberInput(root_scan_id=root.id, display_name="API")],
            ),
        )
        await session.commit()
        ambiguous = await build_portfolio_dashboard(session, portfolio, generated_at=now + timedelta(days=3))
        assert ambiguous.summary.state == "insufficient_evidence"
        assert ambiguous.summary.ambiguous_heads == 1
        assert ambiguous.members[0].evidence_state == "ambiguous_head"
        await upsert_portfolio_member(
            session,
            portfolio,
            PortfolioMemberInput(root_scan_id=root.id, pinned_scan_id=left.id, display_name="API"),
        )
        await session.commit()
        pinned = await build_portfolio_dashboard(session, portfolio, generated_at=now + timedelta(days=3))
    assert pinned.summary.ambiguous_heads == 0
    assert pinned.members[0].pinned is True
    assert pinned.members[0].scan_id == left.id
    assert pinned.members[0].evidence_state == "current"
    await engine.dispose()


async def test_portfolio_governance_versions_and_evidence_hash_are_deterministic(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/integrity.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime(2026, 7, 19, 8, 0, tzinfo=UTC)
    root = Scan(
        id="integrity-root",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "root"),
        created_at=now,
        completed_at=now,
    )
    async with factory() as session:
        await prepare_root(session, root)
        portfolio = await create_portfolio(
            session,
            PortfolioCreate(
                name="Integrity",
                governance=PortfolioGovernanceDocument(max_scan_age_days=365),
                members=[PortfolioMemberInput(root_scan_id=root.id, display_name="Core")],
            ),
        )
        await create_governance_version(
            session,
            portfolio,
            PortfolioGovernanceDocument(max_scan_age_days=365, max_blocked_members=1),
        )
        await session.commit()
        status = await governance_status(session, portfolio.id)
        first = await build_portfolio_dashboard(session, portfolio, generated_at=now + timedelta(days=1))
        second = await build_portfolio_dashboard(session, portfolio, generated_at=now + timedelta(days=1))
    first_bundle = build_portfolio_evidence(first)
    second_bundle = build_portfolio_evidence(second)
    assert status.latest_profile.version == 2
    assert len(status.versions) == 2
    assert first_bundle.integrity.payload_sha256 == second_bundle.integrity.payload_sha256
    assert first_bundle.integrity.section_sha256["members"] == second_bundle.integrity.section_sha256["members"]
    assert first_bundle.versions["portfolio_engine"] == "sentinel-portfolio-governance-v1"
    await engine.dispose()
