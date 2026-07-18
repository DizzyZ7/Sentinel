from collections import Counter
from collections.abc import Iterable

from app.models.finding import Finding
from app.schemas.llm_audit import LLMAuditSummary, LLMReviewRunResponse, ScanLLMAuditResponse


def build_llm_audit_response(scan_id: str, findings: Iterable[Finding]) -> ScanLLMAuditResponse:
    runs = [finding.llm_review for finding in findings if finding.llm_review is not None]
    counts = Counter(run.status for run in runs)
    return ScanLLMAuditResponse(
        scan_id=scan_id,
        summary=LLMAuditSummary(
            total=len(runs),
            completed=counts["completed"],
            failed=counts["failed"],
            skipped=counts["skipped"],
            redactions=sum(run.redaction_count for run in runs),
            input_tokens=sum(run.input_tokens or 0 for run in runs),
            output_tokens=sum(run.output_tokens or 0 for run in runs),
            reasoning_tokens=sum(run.reasoning_tokens or 0 for run in runs),
            total_latency_ms=sum(run.latency_ms or 0 for run in runs),
        ),
        reviews=[LLMReviewRunResponse.model_validate(run) for run in runs],
    )
