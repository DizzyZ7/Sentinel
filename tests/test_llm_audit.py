from datetime import UTC, datetime
from types import SimpleNamespace

from app.services.llm_audit import build_llm_audit_response


def run(status: str, redactions: int, latency: int, input_tokens: int, output_tokens: int):
    return SimpleNamespace(
        id=f"run-{status}-{redactions}",
        finding_id=f"finding-{status}-{redactions}",
        status=status,
        model="gpt-5.6",
        response_id=None,
        prompt_version="v1",
        schema_version="v1",
        context_sha256="a" * 64,
        redaction_count=redactions,
        redaction_summary={"count": redactions, "types": {}, "lines": []},
        retry_count=0,
        latency_ms=latency,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        reasoning_tokens=10,
        error=None,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
    )


def test_llm_audit_summary_aggregates_runs() -> None:
    findings = [
        SimpleNamespace(llm_review=run("completed", 2, 1000, 100, 20)),
        SimpleNamespace(llm_review=run("failed", 1, 500, 50, 0)),
        SimpleNamespace(llm_review=None),
    ]

    response = build_llm_audit_response("scan-1", findings)

    assert response.summary.total == 2
    assert response.summary.completed == 1
    assert response.summary.failed == 1
    assert response.summary.redactions == 3
    assert response.summary.input_tokens == 150
    assert response.summary.output_tokens == 20
    assert response.summary.total_latency_ms == 1500
