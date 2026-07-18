import asyncio
import traceback
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.finding import Finding
from app.models.llm_review import LLMReviewRun
from app.models.scan import Scan
from app.models.verification import RegressionVerification
from app.services.ingestion import prepare_source
from app.services.llm_review import (
    PROMPT_VERSION,
    SCHEMA_VERSION,
    LLMReviewer,
    LLMReviewError,
    ReviewAudit,
    ReviewRequest,
)
from app.services.patches import validate_and_store_patch
from app.services.regression import verify_patch_regression
from app.services.reporting import calculate_risk_score
from app.services.static_analysis import Candidate, analyze_repository, surrounding_context

settings = get_settings()


async def _persist_candidates(
    session: AsyncSession,
    scan_id: str,
    candidates: list[Candidate],
) -> list[Finding]:
    findings = [
        Finding(
            scan_id=scan_id,
            rule_id=item.rule_id,
            title=item.title,
            file_path=item.file_path,
            line=item.line,
            end_line=item.end_line,
            language=item.language,
            snippet=item.snippet,
            static_rationale=item.rationale,
            static_confidence=item.confidence,
        )
        for item in candidates
    ]
    session.add_all(findings)
    await session.flush()
    return findings


def _audit_model(finding_id: str, audit: ReviewAudit) -> LLMReviewRun:
    return LLMReviewRun(
        finding_id=finding_id,
        status=audit.status,
        model=audit.model,
        response_id=audit.response_id,
        prompt_version=audit.prompt_version,
        schema_version=audit.schema_version,
        context_sha256=audit.context_sha256,
        redaction_count=audit.redaction_count,
        redaction_summary=audit.redaction_summary,
        retry_count=audit.retry_count,
        latency_ms=audit.latency_ms,
        input_tokens=audit.input_tokens,
        output_tokens=audit.output_tokens,
        reasoning_tokens=audit.reasoning_tokens,
        error=audit.error,
        started_at=audit.started_at,
        completed_at=audit.completed_at,
    )


def _skipped_audit(finding_id: str, reason: str) -> LLMReviewRun:
    now = datetime.now(UTC)
    return LLMReviewRun(
        finding_id=finding_id,
        status="skipped",
        model=settings.openai_model,
        prompt_version=PROMPT_VERSION,
        schema_version=SCHEMA_VERSION,
        context_sha256=None,
        redaction_count=0,
        redaction_summary={"count": 0, "types": {}, "lines": []},
        retry_count=0,
        latency_ms=0,
        error=reason,
        started_at=now,
        completed_at=now,
    )


async def _review_one(
    reviewer: LLMReviewer,
    repository: Path,
    workspace: Path,
    finding: Finding,
    candidate: Candidate,
) -> None:
    context = surrounding_context(repository, candidate.file_path, candidate.line, radius=50)
    try:
        result = await reviewer.review(ReviewRequest(candidate=candidate, context=context))
    except LLMReviewError as exc:
        finding.llm_status = "failed"
        finding.patch_error = f"LLMReviewError: {exc}"[:1500]
        finding.llm_review = _audit_model(finding.id, exc.audit)
        return
    except Exception as exc:
        finding.llm_status = "failed"
        finding.patch_error = f"{type(exc).__name__}: {exc}"[:1500]
        return

    output = result.output
    finding.llm_review = _audit_model(finding.id, result.audit)
    finding.llm_status = "completed"
    finding.confirmed = output.confirmed
    finding.severity = output.severity if output.confirmed else None
    finding.cvss_score = output.cvss_score if output.confirmed else 0.0
    finding.confidence = output.confidence
    finding.title = output.title
    finding.explanation = output.explanation
    finding.attack_scenario = output.attack_scenario
    finding.recommendation = output.recommendation
    finding.cwe = output.cwe
    finding.unified_diff = output.unified_diff or None

    if not output.confirmed:
        return
    if not output.unified_diff.strip():
        finding.patch_valid = False
        finding.patch_error = "Confirmed finding did not include a patch"
        return

    try:
        validation = await validate_and_store_patch(
            repository=repository,
            patches_dir=workspace / "patches",
            finding_id=finding.id,
            expected_file=finding.file_path,
            diff=output.unified_diff,
            max_bytes=settings.max_patch_bytes,
            max_changed_lines=settings.max_patch_changed_lines,
        )
        finding.patch_valid = validation.valid
        finding.patch_path = str(validation.path) if validation.path else None
        finding.patch_error = validation.error
        if validation.valid and validation.path:
            proof = await verify_patch_regression(
                repository=repository,
                workspace=workspace,
                finding=finding,
                patch_path=validation.path,
            )
            finding.verification = RegressionVerification(
                finding_id=finding.id,
                status=proof.status,
                mode=proof.mode,
                verifier_version=proof.verifier_version,
                before_detected=proof.before_detected,
                after_detected=proof.after_detected,
                patch_applied=proof.patch_applied,
                source_executed=proof.source_executed,
                before_digest=proof.before_digest,
                after_digest=proof.after_digest,
                checks=proof.checks,
                artifact_path=str(proof.artifact_path) if proof.artifact_path else None,
                error=proof.error,
            )
    except Exception as exc:
        finding.patch_valid = False
        finding.patch_error = f"{type(exc).__name__}: {exc}"[:1500]


async def process_scan(scan_id: str) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.error = None
        await session.commit()

    try:
        async with SessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            assert scan is not None
            workspace = Path(scan.workspace_path)
            prepared = await prepare_source(
                workspace=workspace,
                source_type=scan.source_type,
                source_url=scan.source_url,
                archive_path=workspace / "source.zip" if scan.source_type == "zip" else None,
                settings=settings,
            )
            scan.structure = prepared.structure
            scan.file_count = len(prepared.structure)
            scan.status = "prefiltering"
            await session.commit()

        candidates = analyze_repository(prepared.repository, prepared.structure)
        candidates = candidates[: settings.max_llm_candidates]

        async with SessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            assert scan is not None
            await session.execute(delete(Finding).where(Finding.scan_id == scan_id))
            findings = await _persist_candidates(session, scan_id, candidates)
            scan.candidate_count = len(findings)
            scan.status = "reviewing"
            await session.commit()
            finding_ids = [finding.id for finding in findings]

        reviewer = LLMReviewer(settings)
        if reviewer.enabled and candidates:
            async with SessionLocal() as session:
                result = await session.execute(
                    select(Finding).where(Finding.id.in_(finding_ids)).order_by(Finding.file_path, Finding.line)
                )
                findings = list(result.scalars())
                await asyncio.gather(
                    *[
                        _review_one(reviewer, prepared.repository, prepared.workspace, finding, candidate)
                        for finding, candidate in zip(findings, candidates, strict=True)
                    ]
                )
                await session.commit()
        else:
            reason = "LLM disabled or OPENAI_API_KEY not configured"
            async with SessionLocal() as session:
                result = await session.execute(select(Finding).where(Finding.id.in_(finding_ids)))
                for finding in result.scalars():
                    finding.llm_status = "skipped"
                    finding.patch_error = reason
                    finding.llm_review = _skipped_audit(finding.id, reason)
                await session.commit()

        async with SessionLocal() as session:
            result = await session.execute(select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id))
            scan = result.scalar_one()
            confirmed = [
                finding.severity for finding in scan.findings if finding.confirmed and finding.severity is not None
            ]
            scan.finding_count = len(confirmed)
            scan.risk_score = calculate_risk_score(confirmed)
            scan.status = "completed"
            scan.completed_at = datetime.now(UTC)
            await session.commit()
    except Exception as exc:
        async with SessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"[:4000]
                scan.completed_at = datetime.now(UTC)
                await session.commit()
