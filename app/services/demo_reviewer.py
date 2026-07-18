import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path

from app.core.config import Settings
from app.schemas.llm import LLMReviewOutput
from app.services.context_sanitizer import sanitize_context
from app.services.llm_review import PROMPT_VERSION, SCHEMA_VERSION, ReviewAudit, ReviewRequest, ReviewResult


class DemoReviewer:
    """Deterministic, explicitly labelled reviewer for the built-in product tour."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    def enabled(self) -> bool:
        return True

    async def review(self, request: ReviewRequest) -> ReviewResult:
        started_at = datetime.now(UTC)
        started = time.perf_counter()
        candidate = request.candidate
        sanitized = sanitize_context(request.context)
        context_sha256 = hashlib.sha256(sanitized.text.encode("utf-8")).hexdigest()
        filename = Path(candidate.file_path).name

        if filename == "safe_constant.py":
            output = LLMReviewOutput(
                confirmed=False,
                severity="low",
                cvss_score=0.0,
                confidence=0.99,
                title="Constant expression is not attacker controlled",
                explanation=(
                    "The deterministic rule correctly noticed eval, but the supplied expression is a fixed literal "
                    "and no request-derived value reaches the sink."
                ),
                attack_scenario="No attacker-controlled execution path is demonstrated by the supplied evidence.",
                recommendation=(
                    "Prefer ordinary arithmetic for clarity, but do not treat this candidate as exploitable."
                ),
                cwe="CWE-95",
                unified_diff="",
            )
        elif filename == "weak_patch.py":
            output = LLMReviewOutput(
                confirmed=True,
                severity="high",
                cvss_score=8.1,
                confidence=0.98,
                title="SQL injection remains after a cosmetic patch",
                explanation="Request-derived input is interpolated into a SQL statement before execution.",
                attack_scenario="An attacker can alter the item parameter and modify the resulting SQL query.",
                recommendation="Use a parameterized query and pass the value separately.",
                cwe="CWE-89",
                unified_diff=(
                    "--- a/weak_patch.py\n"
                    "+++ b/weak_patch.py\n"
                    "@@ -1,4 +1,4 @@\n"
                    " def load_item(db, request):\n"
                    "     item = request.query_params[\"item\"]\n"
                    "-    query = f\"SELECT * FROM inventory WHERE item = '{item}'\"\n"
                    "+    query = f\"SELECT * FROM inventory WHERE item='{item}'\"\n"
                    "     return db.execute(query)\n"
                ),
            )
        else:
            output = LLMReviewOutput(
                confirmed=True,
                severity="high",
                cvss_score=8.2,
                confidence=0.99,
                title="Request data reaches an interpolated SQL query",
                explanation="The name parameter is copied from the request and embedded directly into SQL.",
                attack_scenario="A crafted name value can escape the quoted value and change the query semantics.",
                recommendation="Use a named parameter and pass request data through the database parameter API.",
                cwe="CWE-89",
                unified_diff=(
                    "--- a/confirmed_sql.py\n"
                    "+++ b/confirmed_sql.py\n"
                    "@@ -1,4 +1,3 @@\n"
                    " def find_user(db, request):\n"
                    "     name = request.query_params[\"name\"]\n"
                    "-    query = f\"SELECT * FROM users WHERE name = '{name}'\"\n"
                    "-    return db.execute(query)\n"
                    "+    return db.execute(\"SELECT * FROM users WHERE name = :name\", {\"name\": name})\n"
                ),
            )

        completed_at = datetime.now(UTC)
        audit = ReviewAudit(
            status="completed",
            model="sentinel-deterministic-demo-replay",
            response_id=f"demo-{filename}-{candidate.rule_id.lower()}",
            prompt_version=PROMPT_VERSION,
            schema_version=SCHEMA_VERSION,
            context_sha256=context_sha256,
            redaction_count=len(sanitized.redactions),
            redaction_summary=sanitized.summary,
            retry_count=0,
            latency_ms=max(1, round((time.perf_counter() - started) * 1000)),
            input_tokens=None,
            output_tokens=None,
            reasoning_tokens=None,
            error=None,
            started_at=started_at,
            completed_at=completed_at,
        )
        return ReviewResult(output=output, audit=audit)
