from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.scan import Scan
from app.schemas.project_context import ProjectAssetContext, ProjectContextDocument
from app.services.lineage import ensure_root_lineage, link_rescan
from app.services.project_context import (
    ProjectContextSnapshot,
    assign_latest_project_context,
    build_project_context_status,
    context_sha256,
    create_project_context_version,
    ensure_project_context,
    load_context_snapshot,
)
from app.services.risk_intelligence import build_risk_intelligence


def context_document() -> ProjectContextDocument:
    return ProjectContextDocument(
        project_name="Payments API",
        environment="production",
        internet_exposed=True,
        default_criticality="high",
        default_exposure="public",
        default_data_classification="confidential",
        compliance_frameworks=["PCI DSS"],
        assets=[
            ProjectAssetContext(
                asset_id="payments",
                name="Payment processing service",
                asset_type="financial_service",
                path_patterns=["app/payments/**"],
                criticality="critical",
                exposure="public",
                data_classification="restricted",
                data_types=["payment records"],
                privilege_required="none",
                business_impact="Payment records can be exposed or altered.",
            )
        ],
    )


def finding(file_path: str = "app/payments/charge.py"):
    return SimpleNamespace(
        id="finding-1",
        rule_id="PY_SQL_INTERPOLATION",
        title="SQL injection",
        file_path=file_path,
        line=7,
        severity="high",
        confirmed=True,
        confidence=0.97,
        static_confidence=0.95,
        llm_status="completed",
        patch_valid=False,
        decision=None,
        verification=None,
        risk_intelligence=None,
    )


async def test_profiles_are_immutable_and_rescans_use_latest_version(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/context.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    now = datetime.now(UTC)
    root = Scan(
        id="root",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(tmp_path / "root"),
        created_at=now,
        completed_at=now,
    )
    child = Scan(
        id="child",
        status="queued",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(tmp_path / "child"),
        created_at=now + timedelta(minutes=1),
    )
    first_document = context_document()
    second_document = first_document.model_copy(update={"environment": "staging"})

    async with factory() as session:
        session.add(root)
        await session.flush()
        await ensure_root_lineage(session, root)
        first = await ensure_project_context(session, root, first_document, source="declared")
        await create_project_context_version(session, root, second_document)
        session.add(child)
        await session.flush()
        await link_rescan(session, root, child)
        assigned_child = await assign_latest_project_context(session, root, child)
        await session.commit()

        root_snapshot = await load_context_snapshot(session, root.id)
        child_snapshot = await load_context_snapshot(session, child.id)
        status = await build_project_context_status(session, root)

    assert first.version == 1
    assert assigned_child.version == 2
    assert root_snapshot is not None and root_snapshot.version == 1
    assert child_snapshot is not None and child_snapshot.version == 2
    assert root_snapshot.context_sha256 != child_snapshot.context_sha256
    assert status.assigned_profile.version == 1
    assert status.latest_profile.version == 2
    assert status.next_rescan_uses_version == 2
    await engine.dispose()


def test_declared_asset_changes_reproducible_risk_inputs() -> None:
    document = context_document()
    snapshot = ProjectContextSnapshot(
        profile_id="profile-1",
        root_scan_id="scan-1",
        version=1,
        source="declared",
        context_sha256=context_sha256(document),
        document=document,
    )
    heuristic = build_risk_intelligence(finding())
    declared = build_risk_intelligence(finding(), snapshot)
    assert heuristic is not None and declared is not None
    assert declared.asset_name == "Payment processing service"
    assert declared.context_asset_id == "payments"
    assert declared.context_profile_version == 1
    assert declared.context_sha256 == snapshot.context_sha256
    assert declared.asset_importance_score == 100.0
    assert declared.data_exposure == "payment records"
    assert declared.business_impact == "Payment records can be exposed or altered."
    assert declared.inherent_risk_score >= heuristic.inherent_risk_score


def test_profile_hash_is_canonical_and_patterns_are_repository_relative() -> None:
    first = context_document()
    second = ProjectContextDocument.model_validate(first.model_dump(mode="json"))
    assert context_sha256(first) == context_sha256(second)
    with pytest.raises(ValidationError):
        ProjectAssetContext(
            asset_id="bad",
            name="Bad",
            path_patterns=["../secrets/**"],
        )
