import asyncio
import json
from dataclasses import dataclass

from openai import AsyncOpenAI

from app.core.config import Settings
from app.schemas.llm import LLMReviewOutput
from app.services.static_analysis import Candidate

SYSTEM_PROMPT = """You are Sentinel, a conservative senior application-security reviewer.
A deterministic scanner produced a CANDIDATE, not a verdict.
Confirm only exploitable or materially unsafe findings.
Use only the supplied line-numbered context.
Do not invent files, functions, frameworks, or trust boundaries.
If confirmed=false, still return a concise explanation and an empty unified_diff.
If confirmed=true, return a minimal unified diff.
Change only the supplied file and avoid broad refactors.
The diff paths must be exactly a/{file_path} and b/{file_path}. Preserve behavior where possible.
Severity logic:
critical = easy remote compromise or credential catastrophe;
high = serious data or code impact;
medium = constrained exploit;
low = defense-in-depth.
Return data matching the required schema and nothing else."""


@dataclass(slots=True)
class ReviewRequest:
    candidate: Candidate
    context: str


class LLMReviewer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = AsyncOpenAI(api_key=settings.openai_api_key) if settings.openai_api_key else None
        self.semaphore = asyncio.Semaphore(settings.llm_max_concurrency)

    @property
    def enabled(self) -> bool:
        return bool(self.settings.llm_enabled and self.client)

    async def review(self, request: ReviewRequest) -> LLMReviewOutput:
        if not self.client:
            raise RuntimeError("OPENAI_API_KEY is not configured")
        candidate = request.candidate
        prompt = {
            "file_path": candidate.file_path,
            "language": candidate.language,
            "candidate_rule": candidate.rule_id,
            "candidate_title": candidate.title,
            "candidate_line": candidate.line,
            "static_rationale": candidate.rationale,
            "static_confidence": candidate.confidence,
            "context": request.context,
        }
        schema = LLMReviewOutput.model_json_schema()
        async with self.semaphore:
            response = await self.client.responses.create(
                model=self.settings.openai_model,
                instructions=SYSTEM_PROMPT.format(file_path=candidate.file_path),
                input=json.dumps(prompt, ensure_ascii=False),
                reasoning={"effort": "medium"},
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "sentinel_security_review",
                        "strict": True,
                        "schema": schema,
                    }
                },
            )
        return LLMReviewOutput.model_validate_json(response.output_text)
