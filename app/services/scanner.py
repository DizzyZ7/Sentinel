import asyncio
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.core.config import Settings, get_settings
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
    ReviewResult,
)
from app.services.patches import validate_and_store_patch
from app.services.progress import add_scan_event
from app.services.project_context import load_context_snapshot
from app.services.regression import verify_patch_regression
from app.services.reporting import calculate_risk_score
from app.services.risk_intelligence import ensure_risk_intelligence
from app.services.security_sla import persist_finding_slas
from app.services.static_analysis import Candidate, analyze_repository, surrounding_context

settings = get_settings()


class Reviewer(Protocol):
    @property
    def enabled(self) -> bool: ...

    async def review(self, request: ReviewRequest) -> ReviewResult: ...


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


def _skipped_audit(finding_id: str, reason: str, pipeline_settings: Settings) -> LLMReviewRun:
    now = datetime.now(UTC)
    return LLMReviewRun(
        finding_id=finding_id,
        status="skipped",
        model=pipeline_settings.openai_model,
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


async def _emit_progress(
    session_factory: async_sessionmaker[AsyncSession],
    scan_id: str,
    stage: str,
    message: str,
    *,
    current: int = 0,
    total: int = 1,
    percent: int | None = None,
    status: str = "active",
) -> None:
    async with session_factory() as session:
        await add_scan_event(
            session,
            scan_id,
            stage,
            message,
            current=current,
            total=total,
            percent=percent,
            status=status,
        )
        await session.commit()


async def _review_one(
    reviewer: Reviewer,
    repository: Path,
    workspace: Path,
    finding: Finding,
    candidate: Candidate,
    pipeline_settings: Settings,
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
            max_bytes=pipeline_settings.max_patch_bytes,
            max_changed_lines=pipeline_settings.max_patch_changed_lines,
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


async def process_scan(
    scan_id: str,
    reviewer: Reviewer | None = None,
    session_factory: async_sessionmaker[AsyncSession] = SessionLocal,
    pipeline_settings: Settings | None = None,
) -> None:
    active_settings = pipeline_settings or settings
    async with session_factory() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.error = None
        await add_scan_event(session, scan_id, "ingesting", "Creating an isolated repository snapshot.", percent=5)
        await session.commit()

    try:
        async with session_factory() as session:
            scan = await session.get(Scan, scan_id)
            assert scan is not None
            workspace = Path(scan.workspace_path)
            prepared = await prepare_source(
                workspace=workspace,
                source_type=scan.source_type,
                source_url=scan.source_url,
                archive_path=workspace / "source.zip" if scan.source_type == "zip" else None,
                settings=active_settings,
            )
            scan.structure = prepared.structure
            scan.file_count = len(prepared.structure)
            scan.status = "prefiltering"
            await add_scan_event(
                session,
                scan_id,
                "indexing",
                f"Indexed {scan.file_count} supported source files.",
                current=scan.file_count,
                total=max(scan.file_count, 1),
                percent=15,
                status="completed",
            )
            await add_scan_event(
                session,
                scan_id,
                "prefiltering",
                "Running deterministic AST and regex triage.",
                percent=20,
            )
            await session.commit()

        candidates = analyze_repository(prepared.repository, prepared.structure)
        candidates = candidates[: active_settings.max_llm_candidates]

        async with session_factory() as session:
            scan = await session.get(Scan, scan_id)
            assert scan is not None
            await session.execute(delete(Finding).where(Finding.scan_id == scan_id))
            findings = await _persist_candidates(session, scan_id, candidates)
            scan.candidate_count = len(findings)
            scan.status = "reviewing"
            review_total = max(len(findings), 1)
            await add_scan_event(
                session,
                scan_id,
                "reviewing",
                f"Deterministic triage produced {len(findings)} review candidates.",
                current=0,
                total=review_total,
                percent=25,
            )
            await session.commit()
            finding_ids = [finding.id for finding in findings]

        active_reviewer = reviewer or LLMReviewer(active_settings)
        if active_reviewer.enabled and candidates:
            async with session_factory() as session:
                result = await session.execute(
                    select(Finding).where(Finding.id.in_(finding_ids)).order_by(Finding.file_path, Finding.line)
                )
                findings = list(result.scalars())
                tasks = [
                    asyncio.create_task(
                        _review_one(
                            active_reviewer,
                            prepared.repository,
                            prepared.workspace,
                            finding,
                            candidate,
                            active_settings,
                        )
                    )
                    for finding, candidate in zip(findings, candidates, strict=True)
                ]
                for completed, task in enumerate(asyncio.as_completed(tasks), start=1):
                    await task
                    percent = 25 + round(60 * completed / len(tasks))
                    await _emit_progress(
                        session_factory,
                        scan_id,
                        "reviewing",
                        f"Reviewed {completed} of {len(tasks)} candidates; validating patches and proofs inline.",
                        current=completed,
                        total=len(tasks),
                        percent=percent,
                    )
                await session.commit()
        else:
            reason = "LLM disabled or OPENAI_API_KEY not configured"
            async with session_factory() as session:
                result = await session.execute(select(Finding).where(Finding.id.in_(finding_ids)))
                for finding in result.scalars():
                    finding.llm_status = "skipped"
                    finding.patch_error = reason
                    finding.llm_review = _skipped_audit(finding.id, reason, active_settings)
                await add_scan_event(
                    session,
                    scan_id,
                    "reviewing",
                    "Deep review skipped; deterministic evidence remains available and the gate fails closed.",
                    current=len(finding_ids),
                    total=max(len(finding_ids), 1),
                    percent=85,
                    status="degraded",
                )
                await session.commit()

        async with session_factory() as session:
            result = await session.execute(select(Scan).options(
                selectinload(Scan.findings).selectinload(Finding.risk_intelligence),
                selectinload(Scan.findings).selectinload(Finding.decision),
                selectinload(Scan.findings).selectinload(Finding.verification),
            ).where(Scan.id == scan_id))
            scan = result.scalar_one()
            await add_scan_event(
                session,
                scan_id,
                "finalizing",
                "Building reports and evaluating release policy.",
                percent=92,
            )
            context_snapshot = await load_context_snapshot(session, scan_id)
            for finding in scan.findings:
                ensure_risk_intelligence(finding, context_snapshot)
            await persist_finding_slas(session, scan, context_snapshot)
            confirmed = [
                finding.severity for finding in scan.findings if finding.confirmed and finding.severity is not None
            ]
            scan.finding_count = len(confirmed)
            scan.risk_score = calculate_risk_score(confirmed)
            scan.status = "completed"
            scan.completed_at = datetime.now(UTC)
            await add_scan_event(
                session,
                scan_id,
                "completed",
                f"Review complete: {scan.finding_count} confirmed findings from {scan.candidate_count} candidates.",
                current=1,
                total=1,
                percent=100,
                status="completed",
            )
            await session.commit()
    except Exception as exc:
        async with session_factory() as session:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"[:4000]
                scan.completed_at = datetime.now(UTC)
                await add_scan_event(
                    session,
                    scan_id,
                    "failed",
                    f"Scan failed safely: {type(exc).__name__}: {exc}",
                    percent=100,
                    status="failed",
                )
                await session.commit()
