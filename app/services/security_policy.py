from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from dataclasses import dataclass

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.lineage import ScanLineage
from app.models.scan import Scan
from app.models.security_policy import ScanPolicyAssignment, SecurityPolicyProfile
from app.schemas.security_policy import (
    PolicyComplianceComparison,
    PolicyComplianceComparisonSummary,
    PolicyComplianceSummary,
    PolicyFindingResult,
    SecurityPolicyCompliance,
    SecurityPolicyDocument,
    SecurityPolicyOverride,
    SecurityPolicyProfileResponse,
    SecurityPolicyStatus,
)
from app.services.policy import SEVERITY_RANK, evaluate_gate
from app.services.project_context import ProjectContextSnapshot
from app.services.risk_intelligence import build_risk_intelligence

POLICY_ENGINE_VERSION = "sentinel-security-policy-v1"


@dataclass(frozen=True, slots=True)
class SecurityPolicySnapshot:
    profile_id: str
    root_scan_id: str
    version: int
    source: str
    policy_sha256: str
    document: SecurityPolicyDocument


def policy_sha256(document: SecurityPolicyDocument) -> str:
    payload = json.dumps(document.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_security_policy(raw: str | None) -> SecurityPolicyDocument | None:
    if raw is None or not raw.strip():
        return None
    try:
        return SecurityPolicyDocument.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError(f"Invalid security policy: {exc}") from exc


def default_security_policy() -> SecurityPolicyDocument:
    return SecurityPolicyDocument(
        policy_name="Sentinel default release policy",
        frameworks=["OWASP ASVS"],
    )


def demo_security_policy() -> SecurityPolicyDocument:
    return SecurityPolicyDocument(
        policy_name="Sentinel production data policy",
        base_block_on="high",
        production_block_on="high",
        public_asset_block_on="medium",
        restricted_data_block_on="medium",
        critical_asset_block_on="medium",
        frameworks=["OWASP ASVS", "SOC 2"],
        overrides=[
            SecurityPolicyOverride(
                override_id="customer-data-release",
                name="Customer data requires verified approval",
                asset_ids=["customer-data-api"],
                block_on="medium",
                require_valid_patch=True,
                require_passed_proof=True,
                require_human_approval=True,
            )
        ],
    )


async def _root_scan_id(db: AsyncSession, scan: Scan) -> str:
    lineage = await db.get(ScanLineage, scan.id)
    return lineage.root_scan_id if lineage else scan.id


async def _latest_profile(db: AsyncSession, root_scan_id: str) -> SecurityPolicyProfile | None:
    result = await db.execute(
        select(SecurityPolicyProfile)
        .where(SecurityPolicyProfile.root_scan_id == root_scan_id)
        .order_by(SecurityPolicyProfile.version.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _profile(db: AsyncSession, profile_id: str) -> SecurityPolicyProfile:
    profile = await db.get(SecurityPolicyProfile, profile_id)
    if profile is None:
        raise ValueError("Assigned security policy profile is missing")
    return profile


def snapshot_from_profile(profile: SecurityPolicyProfile) -> SecurityPolicySnapshot:
    return SecurityPolicySnapshot(
        profile_id=profile.id,
        root_scan_id=profile.root_scan_id,
        version=profile.version,
        source=profile.source,
        policy_sha256=profile.policy_sha256,
        document=SecurityPolicyDocument.model_validate(profile.document),
    )


async def ensure_security_policy(
    db: AsyncSession,
    scan: Scan,
    document: SecurityPolicyDocument | None = None,
    *,
    source: str | None = None,
) -> SecurityPolicyProfile:
    assignment = await db.get(ScanPolicyAssignment, scan.id)
    if assignment:
        return await _profile(db, assignment.profile_id)

    root_scan_id = await _root_scan_id(db, scan)
    latest = await _latest_profile(db, root_scan_id)
    if latest is None:
        active_document = document or default_security_policy()
        active_source = source or ("declared" if document is not None else "inferred")
        latest = SecurityPolicyProfile(
            id=str(uuid.uuid4()),
            root_scan_id=root_scan_id,
            version=1,
            source=active_source,
            policy_sha256=policy_sha256(active_document),
            document=active_document.model_dump(mode="json"),
        )
        db.add(latest)
        await db.flush()
    db.add(ScanPolicyAssignment(scan_id=scan.id, profile_id=latest.id))
    await db.flush()
    return latest


async def assign_latest_security_policy(
    db: AsyncSession,
    baseline: Scan,
    current: Scan,
) -> SecurityPolicyProfile:
    await ensure_security_policy(db, baseline)
    root_scan_id = await _root_scan_id(db, baseline)
    latest = await _latest_profile(db, root_scan_id)
    assert latest is not None
    if await db.get(ScanPolicyAssignment, current.id) is None:
        db.add(ScanPolicyAssignment(scan_id=current.id, profile_id=latest.id))
        await db.flush()
    return latest


async def load_policy_snapshot(db: AsyncSession, scan_id: str) -> SecurityPolicySnapshot | None:
    assignment = await db.get(ScanPolicyAssignment, scan_id)
    if assignment is None:
        return None
    return snapshot_from_profile(await _profile(db, assignment.profile_id))


async def create_security_policy_version(
    db: AsyncSession,
    scan: Scan,
    document: SecurityPolicyDocument,
) -> SecurityPolicyProfile:
    root_scan_id = await _root_scan_id(db, scan)
    latest = await _latest_profile(db, root_scan_id)
    digest = policy_sha256(document)
    if latest is not None and latest.policy_sha256 == digest:
        return latest
    result = await db.execute(
        select(func.max(SecurityPolicyProfile.version)).where(SecurityPolicyProfile.root_scan_id == root_scan_id)
    )
    profile = SecurityPolicyProfile(
        id=str(uuid.uuid4()),
        root_scan_id=root_scan_id,
        version=(result.scalar_one() or 0) + 1,
        source="declared",
        policy_sha256=digest,
        document=document.model_dump(mode="json"),
    )
    db.add(profile)
    await db.flush()
    return profile


def _profile_response(profile: SecurityPolicyProfile, assigned_id: str) -> SecurityPolicyProfileResponse:
    return SecurityPolicyProfileResponse(
        profile_id=profile.id,
        root_scan_id=profile.root_scan_id,
        version=profile.version,
        source=profile.source,
        policy_sha256=profile.policy_sha256,
        document=SecurityPolicyDocument.model_validate(profile.document),
        created_at=profile.created_at,
        assigned_to_current_scan=profile.id == assigned_id,
    )


async def build_security_policy_status(db: AsyncSession, scan: Scan) -> SecurityPolicyStatus:
    assigned = await ensure_security_policy(db, scan)
    result = await db.execute(
        select(SecurityPolicyProfile)
        .where(SecurityPolicyProfile.root_scan_id == assigned.root_scan_id)
        .order_by(SecurityPolicyProfile.version)
    )
    profiles = list(result.scalars())
    latest = profiles[-1]
    return SecurityPolicyStatus(
        scan_id=scan.id,
        root_scan_id=assigned.root_scan_id,
        assigned_profile=_profile_response(assigned, assigned.id),
        latest_profile=_profile_response(latest, assigned.id),
        versions=[_profile_response(profile, assigned.id) for profile in profiles],
        next_rescan_uses_version=latest.version,
    )


def _threshold_applies(severity: str | None, threshold: str) -> bool:
    if threshold == "never" or severity not in SEVERITY_RANK:
        return False
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]


def _minimum_threshold(current: str, candidate: str | None) -> str:
    if candidate is None:
        return current
    return candidate if SEVERITY_RANK[candidate] < SEVERITY_RANK[current] else current


def _override_matches(
    override: SecurityPolicyOverride,
    finding: Finding,
    *,
    asset_id: str | None,
    exposure: str,
    data_classification: str,
    criticality: str,
    environment: str,
    attack_surface: str,
) -> bool:
    if not override.enabled:
        return False
    path = finding.file_path.replace("\\", "/").lstrip("/")
    dimensions = (
        (override.asset_ids, asset_id),
        (override.exposures, exposure),
        (override.data_classifications, data_classification),
        (override.criticalities, criticality),
        (override.environments, environment),
        (override.attack_surfaces, attack_surface),
        (override.severities, finding.severity),
    )
    if any(values and value not in values for values, value in dimensions):
        return False
    if override.path_patterns and not any(fnmatch.fnmatchcase(path, pattern) for pattern in override.path_patterns):
        return False
    return any(
        (
            override.asset_ids,
            override.path_patterns,
            override.exposures,
            override.data_classifications,
            override.criticalities,
            override.environments,
            override.attack_surfaces,
            override.severities,
        )
    )


def evaluate_security_policy(
    scan_id: str,
    findings: list[Finding],
    policy: SecurityPolicySnapshot,
    context: ProjectContextSnapshot | None = None,
) -> SecurityPolicyCompliance:
    document = policy.document
    results: list[PolicyFindingResult] = []
    evaluated = compliant = blocking = unreviewed = matched_override_count = 0

    for finding in findings:
        risk = build_risk_intelligence(finding, context) if finding.confirmed and finding.severity else None
        context_meta = (risk.scoring_factors or {}).get("context", {}) if risk else {}
        exposure = context_meta.get("exposure", risk.exposure if risk else "unknown")
        data_classification = context_meta.get("data_classification", "internal")
        criticality = context_meta.get("criticality", "medium")
        asset_id = context_meta.get("asset_id")
        environment = context.document.environment if context else "unknown"
        attack_surface = risk.attack_surface if risk else "unknown"

        effective = _minimum_threshold("high", document.base_block_on)
        if environment == "production":
            effective = _minimum_threshold(effective, document.production_block_on)
        if exposure == "public":
            effective = _minimum_threshold(effective, document.public_asset_block_on)
        if data_classification == "restricted":
            effective = _minimum_threshold(effective, document.restricted_data_block_on)
        if criticality == "critical":
            effective = _minimum_threshold(effective, document.critical_asset_block_on)

        matched = [
            item
            for item in document.overrides
            if _override_matches(
                item,
                finding,
                asset_id=asset_id,
                exposure=exposure,
                data_classification=data_classification,
                criticality=criticality,
                environment=environment,
                attack_surface=attack_surface,
            )
        ]
        matched_override_count += len(matched)
        for item in matched:
            effective = _minimum_threshold(effective, item.block_on)

        required: list[str] = []
        if _threshold_applies(finding.severity, document.require_valid_patch_from) or any(
            item.require_valid_patch for item in matched
        ):
            required.append("validated_patch")
        if _threshold_applies(finding.severity, document.require_passed_proof_from) or any(
            item.require_passed_proof for item in matched
        ):
            required.append("passed_regression_proof")
        if _threshold_applies(finding.severity, document.require_human_approval_from) or any(
            item.require_human_approval for item in matched
        ):
            required.append("human_approval")

        satisfied: list[str] = []
        if finding.patch_valid:
            satisfied.append("validated_patch")
        if finding.verification and finding.verification.status == "passed":
            satisfied.append("passed_regression_proof")
        if finding.decision and finding.decision.decision == "approved":
            satisfied.append("human_approval")

        blocker_reasons: list[str] = []
        in_scope = bool(
            finding.confirmed
            and finding.severity in SEVERITY_RANK
            and SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[effective]
        )
        if in_scope:
            evaluated += 1
            if finding.decision and finding.decision.decision == "rejected":
                blocker_reasons.append("A human rejected the remediation; the exposure remains open.")
            missing = [control for control in required if control not in satisfied]
            labels = {
                "validated_patch": "A validated patch is required by the assigned security policy.",
                "passed_regression_proof": "A passed non-executing regression proof is required.",
                "human_approval": "Explicit human approval is required before release.",
            }
            blocker_reasons.extend(labels[control] for control in missing)
            if blocker_reasons:
                blocking += 1
            else:
                compliant += 1
        elif (
            document.fail_closed_on_unreviewed
            and finding.llm_status in {"failed", "skipped", "pending"}
            and finding.static_confidence >= document.unreviewed_confidence_threshold
        ):
            evaluated += 1
            blocking += 1
            unreviewed += 1
            blocker_reasons.append(
                "High-confidence deterministic evidence did not complete deep review; policy fails closed."
            )

        results.append(
            PolicyFindingResult(
                finding_id=finding.id,
                rule_id=finding.rule_id,
                title=finding.title,
                file_path=finding.file_path,
                line=finding.line,
                severity=finding.severity,
                effective_block_on=effective,
                in_scope=in_scope,
                context_asset_id=asset_id,
                context_exposure=exposure,
                context_data_classification=data_classification,
                context_criticality=criticality,
                context_environment=environment,
                matched_override_ids=[item.override_id for item in matched],
                required_controls=required,
                satisfied_controls=satisfied,
                blocker_reasons=blocker_reasons,
            )
        )

    base_gate = evaluate_gate(scan_id, findings)
    results_by_id = {item.finding_id: item for item in results}
    for blocker in base_gate.blockers:
        result = results_by_id.get(blocker.finding_id)
        if result is not None and not result.blocker_reasons:
            result.blocker_reasons.append(f"Base release gate: {blocker.reason}")

    blocking = sum(bool(item.blocker_reasons) for item in results)
    compliant = sum(item.in_scope and not item.blocker_reasons for item in results)
    evaluated = sum(item.in_scope or bool(item.blocker_reasons) for item in results)
    return SecurityPolicyCompliance(
        scan_id=scan_id,
        state="blocked" if blocking else "passed",
        passed=blocking == 0,
        policy_profile_id=policy.profile_id,
        policy_version=policy.version,
        policy_sha256=policy.policy_sha256,
        policy_name=document.policy_name,
        base_release_gate=base_gate,
        summary=PolicyComplianceSummary(
            evaluated_findings=evaluated,
            compliant_findings=compliant,
            blocking_findings=blocking,
            unreviewed_blockers=unreviewed,
            matched_overrides=matched_override_count,
        ),
        results=sorted(
            results,
            key=lambda item: (
                0 if item.blocker_reasons else 1,
                -SEVERITY_RANK.get(item.severity or "", 0),
                item.file_path,
                item.line,
            ),
        ),
    )


def compare_policy_compliance(
    baseline: SecurityPolicyCompliance,
    current: SecurityPolicyCompliance,
) -> PolicyComplianceComparison:
    def blocker_keys(payload: SecurityPolicyCompliance) -> set[str]:
        return {
            f"{item.rule_id}:{item.file_path.replace('\\\\', '/').lower()}"
            for item in payload.results
            if item.blocker_reasons
        }

    before = blocker_keys(baseline)
    after = blocker_keys(current)
    return PolicyComplianceComparison(
        baseline_scan_id=baseline.scan_id,
        current_scan_id=current.scan_id,
        baseline=baseline,
        current=current,
        summary=PolicyComplianceComparisonSummary(
            baseline_blockers=len(before),
            current_blockers=len(after),
            introduced=len(after - before),
            resolved=len(before - after),
            persistent=len(before & after),
            state_changed=baseline.state != current.state,
        ),
    )
