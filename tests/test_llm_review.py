import json
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.services.llm_review import LLMReviewer, LLMReviewError, ReviewRequest
from app.services.static_analysis import Candidate


def candidate() -> Candidate:
    return Candidate(
        rule_id="PY_SECRET",
        title="Hardcoded API key",
        file_path="app.py",
        line=2,
        end_line=2,
        language="python",
        snippet='OPENAI_API_KEY = "secret"',
        rationale="A credential-like value is embedded in source.",
        confidence=0.98,
    )


@pytest.mark.asyncio
async def test_reviewer_sanitizes_context_and_returns_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    reviewer = LLMReviewer(Settings(openai_api_key="test-key", llm_max_retries=0))
    reviewer.client = object()
    captured: dict = {}

    async def fake_response(prompt: dict, schema: dict, file_path: str):
        captured.update(prompt)
        return SimpleNamespace(
            id="resp_test_123",
            model="gpt-5.6",
            output_text=json.dumps(
                {
                    "confirmed": True,
                    "severity": "high",
                    "cvss_score": 8.1,
                    "confidence": 0.97,
                    "title": "Hardcoded API credential",
                    "explanation": "A long-lived credential is embedded directly in repository source.",
                    "attack_scenario": "Anyone with source access can reuse the exposed credential.",
                    "recommendation": "Load the credential from a protected environment variable.",
                    "cwe": "CWE-798",
                    "unified_diff": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x\n+y\n",
                }
            ),
            usage=SimpleNamespace(
                input_tokens=120,
                output_tokens=80,
                output_tokens_details=SimpleNamespace(reasoning_tokens=30),
            ),
        )

    monkeypatch.setattr(reviewer, "_create_response", fake_response)
    secret = "sk-proj-abcdefghijklmnop123456"
    result = await reviewer.review(
        ReviewRequest(candidate=candidate(), context=f'1: safe = True\n2: OPENAI_API_KEY = "{secret}"\n')
    )

    serialized_prompt = json.dumps(captured)
    assert secret not in serialized_prompt
    assert "REDACTED_SECRET" in serialized_prompt
    assert result.audit.status == "completed"
    assert result.audit.response_id == "resp_test_123"
    assert result.audit.redaction_count == 1
    assert result.audit.input_tokens == 120
    assert result.audit.output_tokens == 80
    assert result.audit.reasoning_tokens == 30


@pytest.mark.asyncio
async def test_reviewer_failure_preserves_safe_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    reviewer = LLMReviewer(Settings(openai_api_key="test-key", llm_max_retries=0))
    reviewer.client = object()

    async def fail_response(prompt: dict, schema: dict, file_path: str):
        raise ValueError("invalid response sk-proj-abcdefghijklmnop123456")

    monkeypatch.setattr(reviewer, "_create_response", fail_response)

    with pytest.raises(LLMReviewError) as captured:
        await reviewer.review(
            ReviewRequest(
                candidate=candidate(),
                context='OPENAI_API_KEY = "sk-proj-abcdefghijklmnop123456"',
            )
        )

    assert captured.value.audit.status == "failed"
    assert captured.value.audit.redaction_count == 1
    assert "sk-proj" not in (captured.value.audit.error or "")
