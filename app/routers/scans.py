import re
import uuid
from collections import Counter
from pathlib import Path
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.models.decision import ReviewDecision
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.verification import RegressionVerification
from app.schemas.decision import DecisionRequest, DecisionResponse
from app.schemas.finding import FindingResponse
from app.schemas.policy import GateResponse
from app.schemas.scan import ReportResponse, ScanCreated, ScanStatus, SeveritySummary
from app.schemas.verification import (
    RegressionVerificationResponse,
    ScanVerificationResponse,
    VerificationSummary,
)
from app.services.attack_paths import build_attack_path_response, to_mermaid
from app.services.ingestion import IngestionError, save_upload, validate_git_url
from app.services.lineage import ensure_root_lineage
from app.services.policy import evaluate_gate
from app.services.project_context import ensure_project_context, parse_project_context
from app.services.regression import RegressionResult, verify_patch_regression
from app.services.reporting import severity_summary
from app.services.sarif import build_sarif
from app.services.scanner import process_scan
from app.services.security_objective import ensure_security_objective, parse_security_objective
from app.services.security_policy import ensure_security_policy, parse_security_policy
from app.services.security_sla import ensure_security_sla, parse_security_sla

router = APIRouter(prefix="/scan", tags=["scans"])
templates = Jinja2Templates(directory="app/templates")
SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _scan_created(scan: Scan) -> ScanCreated:
    return ScanCreated(
        scan_id=scan.id,
        status=scan.status,
        status_url=f"/scan/{scan.id}",
        report_url=f"/scan/{scan.id}/report",
    )


def _scan_query(scan_id: str):
    return (
        select(Scan)
        .options(
            selectinload(Scan.findings).selectinload(Finding.decision),
            selectinload(Scan.findings).selectinload(Finding.verification),
        )
        .where(Scan.id == scan_id)
    )


async def _load_completed_scan(scan_id: str, db: AsyncSession) -> Scan:
    result = await db.execute(_scan_query(scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=f"Scan is still {scan.status}")
    return scan




def _apply_verification_result(
    finding: Finding,
    proof: RegressionResult,
) -> RegressionVerification:
    verification = finding.verification
    if verification is None:
        verification = RegressionVerification(finding_id=finding.id)
        finding.verification = verification
    verification.status = proof.status
    verification.mode = proof.mode
    verification.verifier_version = proof.verifier_version
    verification.before_detected = proof.before_detected
    verification.after_detected = proof.after_detected
    verification.patch_applied = proof.patch_applied
    verification.source_executed = proof.source_executed
    verification.before_digest = proof.before_digest
    verification.after_digest = proof.after_digest
    verification.checks = proof.checks
    verification.artifact_path = str(proof.artifact_path) if proof.artifact_path else None
    verification.error = proof.error
    return verification

def _ordered_findings(scan: Scan) -> list[Finding]:
    return sorted(
        scan.findings,
        key=lambda finding: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(finding.severity or "", 4),
            finding.file_path,
            finding.line,
        ),
    )


@router.post("/repo", response_model=ScanCreated, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    background_tasks: BackgroundTasks,
    git_url: Annotated[str | None, Form()] = None,
    archive: Annotated[UploadFile | None, File()] = None,
    project_context: Annotated[str | None, Form()] = None,
    security_policy: Annotated[str | None, Form()] = None,
    security_sla: Annotated[str | None, Form()] = None,
    security_objectives: Annotated[str | None, Form()] = None,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ScanCreated:
    if bool(git_url) == bool(archive):
        raise HTTPException(status_code=422, detail="Provide exactly one of git_url or archive")

    try:
        context_document = parse_project_context(project_context)
        policy_document = parse_security_policy(security_policy)
        sla_document = parse_security_sla(security_sla)
        objective_document = parse_security_objective(security_objectives)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    scan_id = str(uuid.uuid4())
    workspace = settings.scans_dir / scan_id
    workspace.mkdir(parents=True, exist_ok=False)

    try:
        if git_url:
            source_url = validate_git_url(git_url, settings.allowed_git_hosts)
            scan = Scan(
                id=scan_id,
                status="queued",
                source_type="git",
                source_url=source_url,
                workspace_path=str(workspace),
            )
        else:
            assert archive is not None
            filename = SAFE_FILENAME_RE.sub("_", archive.filename or "repository.zip")
            if not filename.lower().endswith(".zip"):
                raise IngestionError("Only .zip archives are supported")
            await save_upload(archive, workspace / "source.zip", settings.max_archive_bytes)
            scan = Scan(
                id=scan_id,
                status="queued",
                source_type="zip",
                original_filename=filename,
                workspace_path=str(workspace),
            )
    except IngestionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    db.add(scan)
    await db.flush()
    await ensure_root_lineage(db, scan)
    await ensure_project_context(
        db, scan, context_document, source="declared" if context_document is not None else "inferred"
    )
    await ensure_security_policy(
        db, scan, policy_document, source="declared" if policy_document is not None else "inferred"
    )
    await ensure_security_sla(
        db, scan, sla_document, source="declared" if sla_document is not None else "inferred"
    )
    await ensure_security_objective(
        db, scan, objective_document, source="declared" if objective_document is not None else "inferred"
    )
    await db.commit()
    background_tasks.add_task(process_scan, scan.id)
    return _scan_created(scan)


@router.get("/{scan_id}", response_model=ScanStatus)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> ScanStatus:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatus.model_validate(scan)


@router.get("/{scan_id}/report", response_model=None)
async def get_report(
    request: Request,
    scan_id: str,
    format: Literal["json", "html", "sarif"] | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_completed_scan(scan_id, db)
    ordered_findings = _ordered_findings(scan)

    if format == "sarif":
        return JSONResponse(
            build_sarif(ordered_findings),
            media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="sentinel-{scan.id}.sarif"'},
        )

    confirmed_severities = [
        finding.severity for finding in ordered_findings if finding.confirmed and finding.severity is not None
    ]
    payload = ReportResponse(
        **ScanStatus.model_validate(scan).model_dump(),
        severity_summary=SeveritySummary(**severity_summary(confirmed_severities)),
        findings=[FindingResponse.model_validate(item) for item in ordered_findings],
        structure=scan.structure,
    )

    wants_html = format == "html" or (format is None and "text/html" in request.headers.get("accept", ""))
    if wants_html:
        attack_paths = build_attack_path_response(scan.id, ordered_findings)
        gate = evaluate_gate(scan.id, ordered_findings)
        return templates.TemplateResponse(
            request=request,
            name="report.html",
            context={
                "report": payload.model_dump(mode="json"),
                "attack_paths": attack_paths.model_dump(mode="json"),
                "gate": gate.model_dump(mode="json"),
            },
        )
    return payload


@router.get("/{scan_id}/attack-paths", response_model=None)
async def get_attack_paths(
    scan_id: str,
    format: Literal["json", "mermaid"] = Query(default="json"),
    db: AsyncSession = Depends(get_db),
):
    scan = await _load_completed_scan(scan_id, db)
    payload = build_attack_path_response(scan.id, _ordered_findings(scan))
    if format == "mermaid":
        return PlainTextResponse(
            to_mermaid(payload),
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="sentinel-{scan.id}.mmd"'},
        )
    return payload


@router.get("/{scan_id}/gate", response_model=GateResponse)
async def get_release_gate(
    scan_id: str,
    block_on: Literal["critical", "high", "medium", "low"] = Query(default="high"),
    fail_closed_on_unreviewed: bool = Query(default=True),
    db: AsyncSession = Depends(get_db),
) -> GateResponse:
    scan = await _load_completed_scan(scan_id, db)
    return evaluate_gate(
        scan.id,
        _ordered_findings(scan),
        block_on=block_on,
        fail_closed_on_unreviewed=fail_closed_on_unreviewed,
    )


@router.get("/{scan_id}/verifications", response_model=ScanVerificationResponse)
async def get_verifications(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> ScanVerificationResponse:
    scan = await _load_completed_scan(scan_id, db)
    verifications = [finding.verification for finding in _ordered_findings(scan) if finding.verification]
    counts = Counter(item.status for item in verifications)
    return ScanVerificationResponse(
        scan_id=scan.id,
        summary=VerificationSummary(
            total=len(verifications),
            passed=counts["passed"],
            failed=counts["failed"],
            inconclusive=counts["inconclusive"],
            skipped=counts["skipped"],
        ),
        verifications=[RegressionVerificationResponse.model_validate(item) for item in verifications],
    )


@router.get(
    "/{scan_id}/findings/{finding_id}/verification",
    response_model=RegressionVerificationResponse,
)
async def get_finding_verification(
    scan_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> RegressionVerificationResponse:
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.verification))
        .where(Finding.id == finding_id, Finding.scan_id == scan_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.verification:
        raise HTTPException(status_code=404, detail="Regression verification not available")
    return RegressionVerificationResponse.model_validate(finding.verification)


@router.get(
    "/{scan_id}/findings/{finding_id}/verification/artifact",
    response_class=FileResponse,
)
async def download_verification_artifact(
    scan_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.verification))
        .where(Finding.id == finding_id, Finding.scan_id == scan_id)
    )
    finding = result.scalar_one_or_none()
    if not finding or not finding.verification or not finding.verification.artifact_path:
        raise HTTPException(status_code=404, detail="Verification artifact not found")
    scan = await db.get(Scan, scan_id)
    assert scan is not None
    workspace = Path(scan.workspace_path).resolve()
    artifact = Path(finding.verification.artifact_path).resolve()
    if not artifact.is_relative_to(workspace) or not artifact.is_file():
        raise HTTPException(status_code=409, detail="Verification artifact is unavailable")
    return FileResponse(
        artifact,
        media_type="application/json",
        filename=f"sentinel-regression-{finding.id}.json",
    )


@router.post(
    "/{scan_id}/findings/{finding_id}/verification/recheck",
    response_model=RegressionVerificationResponse,
)
async def recheck_finding_verification(
    scan_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> RegressionVerificationResponse:
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.verification))
        .where(Finding.id == finding_id, Finding.scan_id == scan_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.patch_valid or not finding.patch_path:
        raise HTTPException(status_code=409, detail="A validated patch is required for regression verification")
    scan = await db.get(Scan, scan_id)
    assert scan is not None
    workspace = Path(scan.workspace_path).resolve()
    repository = workspace / "repo"
    patch_path = Path(finding.patch_path).resolve()
    if not patch_path.is_relative_to(workspace) or not patch_path.is_file():
        raise HTTPException(status_code=409, detail="Patch artifact is unavailable")
    proof = await verify_patch_regression(repository, workspace, finding, patch_path)
    verification = _apply_verification_result(finding, proof)
    db.add(verification)
    await db.commit()
    await db.refresh(verification)
    return RegressionVerificationResponse.model_validate(verification)


@router.get("/{scan_id}/findings/{finding_id}/patch", response_class=FileResponse)
async def download_patch(scan_id: str, finding_id: str, db: AsyncSession = Depends(get_db)) -> FileResponse:
    result = await db.execute(
        select(Finding).join(Scan).where(Finding.id == finding_id, Finding.scan_id == scan_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.patch_valid or not finding.patch_path:
        raise HTTPException(status_code=409, detail="Finding does not have a validated patch")

    scan = await db.get(Scan, scan_id)
    assert scan is not None
    workspace = Path(scan.workspace_path).resolve()
    patch_path = Path(finding.patch_path).resolve()
    if not patch_path.is_relative_to(workspace) or not patch_path.is_file():
        raise HTTPException(status_code=409, detail="Patch artifact is unavailable")
    return FileResponse(
        patch_path,
        media_type="text/x-diff",
        filename=f"sentinel-{finding.rule_id}-{finding.id}.patch",
    )


@router.post(
    "/{scan_id}/findings/{finding_id}/decision",
    response_model=DecisionResponse,
)
async def decide_finding(
    scan_id: str,
    finding_id: str,
    payload: DecisionRequest,
    db: AsyncSession = Depends(get_db),
) -> DecisionResponse:
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.decision), selectinload(Finding.verification))
        .where(Finding.id == finding_id, Finding.scan_id == scan_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.confirmed:
        raise HTTPException(status_code=409, detail="Only confirmed findings require a human decision")
    if payload.decision == "approved" and not finding.patch_valid:
        raise HTTPException(status_code=409, detail="Only a validated patch can be approved")
    if payload.decision == "approved" and (
        not finding.verification or finding.verification.status != "passed"
    ):
        raise HTTPException(
            status_code=409,
            detail="Only a patch with a passed non-executing regression proof can be approved",
        )

    decision = finding.decision
    if decision is None:
        decision = ReviewDecision(finding_id=finding.id, decision=payload.decision, note=payload.note)
        db.add(decision)
    else:
        decision.decision = payload.decision
        decision.note = payload.note
    await db.commit()
    await db.refresh(decision)
    return DecisionResponse.model_validate(decision)


@router.get("", response_model=list[ScanStatus])
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> list[ScanStatus]:
    result = await db.execute(select(Scan).order_by(desc(Scan.created_at)).limit(limit))
    return [ScanStatus.model_validate(scan) for scan in result.scalars()]
