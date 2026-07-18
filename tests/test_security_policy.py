from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models import Base
from app.models.decision import ReviewDecision
from app.models.scan import Scan
from app.models.verification import RegressionVerification
from app.schemas.project_context import ProjectAssetContext, ProjectContextDocument
from app.schemas.security_policy import SecurityPolicyDocument, SecurityPolicyOverride
from app.services.lineage import ensure_root_lineage, link_rescan
from app.services.project_context import ProjectContextSnapshot, context_sha256
from app.services.security_policy import (
    SecurityPolicySnapshot,
    assign_latest_security_policy,
    build_security_policy_status,
    compare_policy_compliance,
    create_security_policy_version,
    ensure_security_policy,
    evaluate_security_policy,
    load_policy_snapshot,
    policy_sha256,
)


def finding(*, severity: str = "medium", approved: bool = False):
    decision = ReviewDecision(
        finding_id="finding-1",
        decision="approved" if approved else "rejected"
    ) if approved else None
    verification = RegressionVerification(
        finding_id="finding-1",
        status="passed",
        mode="deterministic",
        verifier_version="v1",
        before_detected=True,
        after_detected=False,
        patch_applied=True,
        source_executed=False,
        checks=[],
    ) if approved else None
    return SimpleNamespace(
        id="finding-1",
        rule_id="PY_SQL_INTERPOLATION",
        title="SQL injection",
        file_path="app/payments/query.py",
        line=8,
        severity=severity,
        confirmed=True,
        confidence=0.97,
        static_confidence=0.96,
        llm_status="completed",
        patch_valid=approved,
        decision=decision,
        verification=verification,
        risk_intelligence=None,
    )


def context() -> ProjectContextSnapshot:
    document = ProjectContextDocument(
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
                data_types=["payment records"],
            )
        ],
    )
    return ProjectContextSnapshot(
        profile_id="context-1",
        root_scan_id="scan-1",
        version=1,
        source="declared",
        context_sha256=context_sha256(document),
        document=document,
    )


def policy() -> SecurityPolicySnapshot:
    document = SecurityPolicyDocument(
        policy_name="Production policy",
        base_block_on="high",
        public_asset_block_on="medium",
        restricted_data_block_on="medium",
        critical_asset_block_on="medium",
        overrides=[
            SecurityPolicyOverride(
                override_id="payments",
                name="Payments proof",
                asset_ids=["payments-api"],
                require_valid_patch=True,
                require_passed_proof=True,
                require_human_approval=True,
            )
        ],
    )
    return SecurityPolicySnapshot(
        profile_id="policy-1",
        root_scan_id="scan-1",
        version=1,
        source="declared",
        policy_sha256=policy_sha256(document),
        document=document,
    )


def test_context_can_strengthen_threshold_and_require_controls() -> None:
    blocked = evaluate_security_policy("scan-1", [finding()], policy(), context())
    assert blocked.state == "blocked"
    result = blocked.results[0]
    assert result.effective_block_on == "medium"
    assert result.context_asset_id == "payments-api"
    assert result.matched_override_ids == ["payments"]
    assert result.required_controls == [
        "validated_patch",
        "passed_regression_proof",
        "human_approval",
    ]
    assert len(result.blocker_reasons) == 3

    passed = evaluate_security_policy("scan-1", [finding(approved=True)], policy(), context())
    assert passed.state == "passed"
    assert passed.summary.compliant_findings == 1


def test_policy_comparison_classifies_blocker_changes() -> None:
    before = evaluate_security_policy("baseline", [finding()], policy(), context())
    after = evaluate_security_policy("current", [finding(approved=True)], policy(), context())
    comparison = compare_policy_compliance(before, after)
    assert comparison.summary.baseline_blockers == 1
    assert comparison.summary.current_blockers == 0
    assert comparison.summary.resolved == 1
    assert comparison.summary.state_changed is True


async def test_policy_versions_are_immutable_and_rescan_uses_latest(tmp_path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/policy.db")
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    now = datetime.now(UTC)
    root = Scan(
        id="root",
        status="completed",
        source_type="zip",
        workspace_path=str(tmp_path / "root"),
        created_at=now,
    )
    child = Scan(
        id="child",
        status="queued",
        source_type="zip",
        workspace_path=str(tmp_path / "child"),
        created_at=now + timedelta(minutes=1),
    )
    first_document = SecurityPolicyDocument(policy_name="v1")
    second_document = first_document.model_copy(update={"base_block_on": "medium"})
    async with factory() as session:
        session.add(root)
        await session.flush()
        await ensure_root_lineage(session, root)
        first = await ensure_security_policy(session, root, first_document, source="declared")
        await create_security_policy_version(session, root, second_document)
        session.add(child)
        await session.flush()
        await link_rescan(session, root, child)
        assigned = await assign_latest_security_policy(session, root, child)
        await session.commit()
        root_snapshot = await load_policy_snapshot(session, root.id)
        child_snapshot = await load_policy_snapshot(session, child.id)
        status = await build_security_policy_status(session, root)
    assert first.version == 1
    assert assigned.version == 2
    assert root_snapshot and root_snapshot.version == 1
    assert child_snapshot and child_snapshot.version == 2
    assert status.assigned_profile.version == 1
    assert status.latest_profile.version == 2
    await engine.dispose()


def test_policy_hash_is_canonical_and_patterns_are_safe() -> None:
    document = SecurityPolicyDocument(policy_name="Policy")
    assert policy_sha256(document) == policy_sha256(SecurityPolicyDocument.model_validate(document.model_dump()))
    with pytest.raises(ValidationError):
        SecurityPolicyOverride(override_id="bad", name="Bad", path_patterns=["../secret/**"])
