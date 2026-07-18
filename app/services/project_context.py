from __future__ import annotations

import fnmatch
import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import urlparse

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.lineage import ScanLineage
from app.models.project_context import ProjectContextProfile, ScanContextAssignment
from app.models.scan import Scan
from app.schemas.project_context import (
    ProjectAssetContext,
    ProjectContextDocument,
    ProjectContextProfileResponse,
    ProjectContextStatus,
)

CRITICALITY_SCORE = {"low": 0.42, "medium": 0.65, "high": 0.85, "critical": 1.0}
EXPOSURE_SCORE = {"unknown": 0.45, "internal": 0.35, "partner": 0.65, "public": 0.95}
ENVIRONMENT_MODIFIER = {"unknown": 0.0, "development": 0.0, "staging": 0.02, "production": 0.05}
DATA_MODIFIER = {"public": 0.0, "internal": 0.0, "confidential": 0.04, "restricted": 0.08}


@dataclass(frozen=True, slots=True)
class ProjectContextSnapshot:
    profile_id: str
    root_scan_id: str
    version: int
    source: str
    context_sha256: str
    document: ProjectContextDocument


@dataclass(frozen=True, slots=True)
class ResolvedProjectContext:
    source: str
    asset_id: str | None
    asset_name: str
    asset_type: str
    component: str
    asset_importance: float
    exposure: str
    exposure_score: float
    data_exposure: str
    privilege_required: str
    business_impact: str


def context_sha256(document: ProjectContextDocument) -> str:
    payload = json.dumps(document.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_project_context(raw: str | None) -> ProjectContextDocument | None:
    if raw is None or not raw.strip():
        return None
    try:
        return ProjectContextDocument.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError(f"Invalid project context: {exc}") from exc


def _project_name(scan: Scan) -> str:
    if scan.source_type == "git" and scan.source_url:
        path = urlparse(scan.source_url).path.rstrip("/")
        return PurePosixPath(path).stem or "Git repository"
    if scan.original_filename:
        return PurePosixPath(scan.original_filename).stem or "ZIP repository"
    return "Sentinel project"


def default_project_context(scan: Scan) -> ProjectContextDocument:
    return ProjectContextDocument(project_name=_project_name(scan))


def demo_project_context() -> ProjectContextDocument:
    return ProjectContextDocument(
        project_name="Sentinel judge demo",
        environment="production",
        internet_exposed=True,
        default_criticality="high",
        default_exposure="public",
        default_data_classification="confidential",
        compliance_frameworks=["OWASP ASVS"],
        assets=[
            ProjectAssetContext(
                asset_id="customer-data-api",
                name="Customer data API",
                asset_type="data_service",
                path_patterns=["**/confirmed_sql.py", "confirmed_sql.py"],
                criticality="critical",
                exposure="public",
                data_classification="restricted",
                data_types=["customer records", "account identifiers"],
                privilege_required="none",
                business_impact="Compromise can expose or modify customer records across the application database.",
                owner="Application security demo",
            ),
            ProjectAssetContext(
                asset_id="inventory-query-service",
                name="Inventory query service",
                asset_type="data_service",
                path_patterns=["**/weak_patch.py", "weak_patch.py"],
                criticality="critical",
                exposure="partner",
                data_classification="confidential",
                data_types=["inventory records", "item metadata"],
                privilege_required="authenticated",
                business_impact="Compromise can expose or alter inventory records through the application database.",
                owner="Application security demo",
            ),
        ],
    )


async def _root_scan_id(db: AsyncSession, scan: Scan) -> str:
    lineage = await db.get(ScanLineage, scan.id)
    return lineage.root_scan_id if lineage else scan.id


async def _latest_profile(db: AsyncSession, root_scan_id: str) -> ProjectContextProfile | None:
    result = await db.execute(
        select(ProjectContextProfile)
        .where(ProjectContextProfile.root_scan_id == root_scan_id)
        .order_by(ProjectContextProfile.version.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def _profile(db: AsyncSession, profile_id: str) -> ProjectContextProfile:
    profile = await db.get(ProjectContextProfile, profile_id)
    if profile is None:
        raise ValueError("Assigned project context profile is missing")
    return profile


def snapshot_from_profile(profile: ProjectContextProfile) -> ProjectContextSnapshot:
    return ProjectContextSnapshot(
        profile_id=profile.id,
        root_scan_id=profile.root_scan_id,
        version=profile.version,
        source=profile.source,
        context_sha256=profile.context_sha256,
        document=ProjectContextDocument.model_validate(profile.document),
    )


async def ensure_project_context(
    db: AsyncSession,
    scan: Scan,
    document: ProjectContextDocument | None = None,
    *,
    source: str | None = None,
) -> ProjectContextProfile:
    assignment = await db.get(ScanContextAssignment, scan.id)
    if assignment:
        return await _profile(db, assignment.profile_id)

    root_scan_id = await _root_scan_id(db, scan)
    latest = await _latest_profile(db, root_scan_id)
    if latest is None:
        active_document = document or default_project_context(scan)
        active_source = source or ("declared" if document is not None else "inferred")
        latest = ProjectContextProfile(
            id=str(uuid.uuid4()),
            root_scan_id=root_scan_id,
            version=1,
            source=active_source,
            context_sha256=context_sha256(active_document),
            document=active_document.model_dump(mode="json"),
        )
        db.add(latest)
        await db.flush()
    assignment = ScanContextAssignment(scan_id=scan.id, profile_id=latest.id)
    db.add(assignment)
    await db.flush()
    return latest


async def assign_latest_project_context(db: AsyncSession, baseline: Scan, current: Scan) -> ProjectContextProfile:
    await ensure_project_context(db, baseline)
    root_scan_id = await _root_scan_id(db, baseline)
    latest = await _latest_profile(db, root_scan_id)
    assert latest is not None
    existing = await db.get(ScanContextAssignment, current.id)
    if existing is None:
        db.add(ScanContextAssignment(scan_id=current.id, profile_id=latest.id))
        await db.flush()
    return latest


async def load_context_snapshot(db: AsyncSession, scan_id: str) -> ProjectContextSnapshot | None:
    assignment = await db.get(ScanContextAssignment, scan_id)
    if assignment is None:
        return None
    return snapshot_from_profile(await _profile(db, assignment.profile_id))


async def create_project_context_version(
    db: AsyncSession,
    scan: Scan,
    document: ProjectContextDocument,
) -> ProjectContextProfile:
    root_scan_id = await _root_scan_id(db, scan)
    result = await db.execute(
        select(func.max(ProjectContextProfile.version)).where(ProjectContextProfile.root_scan_id == root_scan_id)
    )
    latest_version = result.scalar_one() or 0
    latest = await _latest_profile(db, root_scan_id)
    digest = context_sha256(document)
    if latest is not None and latest.context_sha256 == digest:
        return latest
    version = latest_version + 1
    profile = ProjectContextProfile(
        id=str(uuid.uuid4()),
        root_scan_id=root_scan_id,
        version=version,
        source="declared",
        context_sha256=digest,
        document=document.model_dump(mode="json"),
    )
    db.add(profile)
    await db.flush()
    return profile


def _profile_response(profile: ProjectContextProfile, assigned_id: str) -> ProjectContextProfileResponse:
    return ProjectContextProfileResponse(
        profile_id=profile.id,
        root_scan_id=profile.root_scan_id,
        version=profile.version,
        source=profile.source,
        context_sha256=profile.context_sha256,
        document=ProjectContextDocument.model_validate(profile.document),
        created_at=profile.created_at,
        assigned_to_current_scan=profile.id == assigned_id,
    )


async def build_project_context_status(db: AsyncSession, scan: Scan) -> ProjectContextStatus:
    assigned = await ensure_project_context(db, scan)
    result = await db.execute(
        select(ProjectContextProfile)
        .where(ProjectContextProfile.root_scan_id == assigned.root_scan_id)
        .order_by(ProjectContextProfile.version)
    )
    profiles = list(result.scalars())
    latest = profiles[-1]
    return ProjectContextStatus(
        scan_id=scan.id,
        root_scan_id=assigned.root_scan_id,
        assigned_profile=_profile_response(assigned, assigned.id),
        latest_profile=_profile_response(latest, assigned.id),
        versions=[_profile_response(profile, assigned.id) for profile in profiles],
        next_rescan_uses_version=latest.version,
    )


def _pattern_specificity(pattern: str) -> int:
    return sum(character not in "*?[]" for character in pattern)


def _matching_asset(document: ProjectContextDocument, file_path: str) -> ProjectAssetContext | None:
    normalized = file_path.replace("\\", "/").lstrip("/")
    matches: list[tuple[int, str, ProjectAssetContext]] = []
    for asset in document.assets:
        for pattern in asset.path_patterns:
            if fnmatch.fnmatchcase(normalized, pattern) or PurePosixPath(normalized).match(pattern):
                matches.append((_pattern_specificity(pattern), asset.asset_id, asset))
    return sorted(matches, key=lambda item: (-item[0], item[1]))[0][2] if matches else None


def _importance(criticality: str, environment: str, data_classification: str) -> float:
    return min(
        1.0,
        CRITICALITY_SCORE[criticality]
        + ENVIRONMENT_MODIFIER[environment]
        + DATA_MODIFIER[data_classification],
    )


def resolve_project_context(
    snapshot: ProjectContextSnapshot | None,
    *,
    file_path: str,
    fallback_asset_name: str,
    fallback_asset_type: str,
    fallback_component: str,
    fallback_asset_importance: float,
    fallback_exposure: str,
    fallback_exposure_score: float,
    fallback_data_exposure: str,
    fallback_privilege_required: str,
    fallback_business_impact: str,
) -> ResolvedProjectContext:
    if snapshot is None or (snapshot.source == "inferred" and not snapshot.document.assets):
        return ResolvedProjectContext(
            source="heuristic",
            asset_id=None,
            asset_name=fallback_asset_name,
            asset_type=fallback_asset_type,
            component=fallback_component,
            asset_importance=fallback_asset_importance,
            exposure=fallback_exposure,
            exposure_score=fallback_exposure_score,
            data_exposure=fallback_data_exposure,
            privilege_required=fallback_privilege_required,
            business_impact=fallback_business_impact,
        )

    document = snapshot.document
    asset = _matching_asset(document, file_path)
    if asset is not None:
        data_exposure = ", ".join(asset.data_types) or f"{asset.data_classification} project data"
        return ResolvedProjectContext(
            source="asset_profile",
            asset_id=asset.asset_id,
            asset_name=asset.name,
            asset_type=asset.asset_type,
            component=fallback_component,
            asset_importance=_importance(asset.criticality, document.environment, asset.data_classification),
            exposure=asset.exposure,
            exposure_score=EXPOSURE_SCORE[asset.exposure],
            data_exposure=data_exposure,
            privilege_required=asset.privilege_required or fallback_privilege_required,
            business_impact=asset.business_impact or fallback_business_impact,
        )

    exposure = document.default_exposure
    if document.internet_exposed is True and exposure == "unknown":
        exposure = "public"
    return ResolvedProjectContext(
        source="profile_default",
        asset_id=None,
        asset_name=fallback_asset_name,
        asset_type=fallback_asset_type,
        component=fallback_component,
        asset_importance=_importance(
            document.default_criticality,
            document.environment,
            document.default_data_classification,
        ),
        exposure=exposure,
        exposure_score=EXPOSURE_SCORE[exposure],
        data_exposure=f"{document.default_data_classification} project data",
        privilege_required=fallback_privilege_required,
        business_impact=fallback_business_impact,
    )
