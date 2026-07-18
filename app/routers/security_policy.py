import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.finding import Finding
from app.models.lineage import ScanLineage
from app.models.scan import Scan
from app.schemas.security_policy import (
    PolicyComplianceComparison,
    SecurityPolicyCompliance,
    SecurityPolicyDocument,
    SecurityPolicyPreview,
    SecurityPolicyStatus,
)
from app.services.project_context import load_context_snapshot
from app.services.security_policy import (
    SecurityPolicySnapshot,
    build_security_policy_status,
    compare_policy_compliance,
    create_security_policy_version,
    ensure_security_policy,
    evaluate_security_policy,
    load_policy_snapshot,
    policy_sha256,
)

router = APIRouter(prefix="/scan", tags=["security-policy"])
templates = Jinja2Templates(directory="app/templates")


def _scan_query(scan_id: str):
    return (
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
            selectinload(Scan.findings).selectinload(Finding.risk_intelligence),
        )
        .where(Scan.id == scan_id)
    )


async def _load_scan(scan_id: str, db: AsyncSession, *, finished: bool = False) -> Scan:
    result = await db.execute(_scan_query(scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if finished and scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")
    return scan


async def _compliance(scan: Scan, db: AsyncSession) -> SecurityPolicyCompliance:
    await ensure_security_policy(db, scan)
    policy = await load_policy_snapshot(db, scan.id)
    assert policy is not None
    context = await load_context_snapshot(db, scan.id)
    return evaluate_security_policy(scan.id, list(scan.findings), policy, context)


@router.get("/{scan_id}/security-policy", response_model=None)
async def get_security_policy(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan(scan_id, db)
    status = await build_security_policy_status(db, scan)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="security_policy.html",
            context={
                "scan": scan,
                "status": status,
                "document_json": json.dumps(
                    status.latest_profile.document.model_dump(mode="json"), indent=2, ensure_ascii=False
                ),
            },
        )
    return SecurityPolicyStatus.model_validate(status)


@router.put("/{scan_id}/security-policy", response_model=SecurityPolicyStatus)
async def create_security_policy_profile(
    scan_id: str,
    document: SecurityPolicyDocument,
    db: AsyncSession = Depends(get_db),
) -> SecurityPolicyStatus:
    scan = await _load_scan(scan_id, db)
    await build_security_policy_status(db, scan)
    await create_security_policy_version(db, scan, document)
    await db.commit()
    return SecurityPolicyStatus.model_validate(await build_security_policy_status(db, scan))


@router.post("/{scan_id}/security-policy/preview", response_model=SecurityPolicyPreview)
async def preview_security_policy(
    scan_id: str,
    document: SecurityPolicyDocument,
    db: AsyncSession = Depends(get_db),
) -> SecurityPolicyPreview:
    scan = await _load_scan(scan_id, db, finished=True)
    assigned = await load_policy_snapshot(db, scan.id)
    root_scan_id = assigned.root_scan_id if assigned else scan.id
    digest = policy_sha256(document)
    snapshot = SecurityPolicySnapshot(
        profile_id="preview",
        root_scan_id=root_scan_id,
        version=0,
        source="preview",
        policy_sha256=digest,
        document=document,
    )
    context = await load_context_snapshot(db, scan.id)
    compliance = evaluate_security_policy(scan.id, list(scan.findings), snapshot, context)
    return SecurityPolicyPreview(scan_id=scan.id, policy_sha256=digest, compliance=compliance)


@router.get("/{scan_id}/policy-compliance", response_model=None)
async def get_policy_compliance(
    request: Request,
    scan_id: str,
    format: Literal["json", "html"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_scan(scan_id, db, finished=True)
    compliance = await _compliance(scan, db)
    await db.commit()
    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        return templates.TemplateResponse(
            request=request,
            name="policy_compliance.html",
            context={"scan": scan, "compliance": compliance},
        )
    return SecurityPolicyCompliance.model_validate(compliance)


@router.get(
    "/{current_scan_id}/policy-compliance/compare/{baseline_scan_id}",
    response_model=PolicyComplianceComparison,
)
async def compare_policy_compliance_endpoint(
    current_scan_id: str,
    baseline_scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> PolicyComplianceComparison:
    if current_scan_id == baseline_scan_id:
        raise HTTPException(status_code=422, detail="Current and baseline scans must be different")
    current = await _load_scan(current_scan_id, db, finished=True)
    baseline = await _load_scan(baseline_scan_id, db, finished=True)
    current_lineage = await db.get(ScanLineage, current.id)
    baseline_lineage = await db.get(ScanLineage, baseline.id)
    current_root = current_lineage.root_scan_id if current_lineage else current.id
    baseline_root = baseline_lineage.root_scan_id if baseline_lineage else baseline.id
    if current_root != baseline_root:
        raise HTTPException(status_code=422, detail="Scans must belong to the same lineage")
    comparison = compare_policy_compliance(
        await _compliance(baseline, db),
        await _compliance(current, db),
    )
    await db.commit()
    return comparison
