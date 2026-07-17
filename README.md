# Sentinel

**Sentinel is a local-first evidence-to-patch security agent powered by GPT-5.6.** It scans Python and JavaScript/TypeScript repositories, uses deterministic rules to find review candidates, asks GPT-5.6 to confirm or reject each candidate, generates a minimal unified diff, validates it with `git apply --check`, and leaves the final decision to a human.

> Sentinel never auto-applies security patches. Every proposed change is kept in patch escrow for review.

## Why this is different

Traditional SAST is noisy; unconstrained AI code review can hallucinate. Sentinel deliberately combines both:

1. **Cheap deterministic triage** — AST and regex rules create candidates, not verdicts.
2. **Evidence-bound GPT-5.6 review** — the model receives the finding plus 50 surrounding lines and must return strict JSON.
3. **Executable patch verification** — every diff is path-restricted and checked against the repository.
4. **Human-in-the-loop boundary** — patches are stored, never applied automatically.

## Run in 3 commands

```bash
cp .env.example .env
# Add OPENAI_API_KEY to .env
docker compose up --build -d
curl -F "archive=@demo/archives/python-vulnerable.zip" http://localhost:8000/scan/repo
```

Open `http://localhost:8000` for the upload UI and `http://localhost:8000/docs` for OpenAPI.

Without an API key, ingestion and static analysis still run; candidates are marked `llm_status=skipped`.

## API

### Start a ZIP scan

```bash
curl -F "archive=@demo/archives/node-vulnerable.zip" http://localhost:8000/scan/repo
```

### Start a Git scan

```bash
curl -F "git_url=https://github.com/owner/repository.git" http://localhost:8000/scan/repo
```

For safety, Git hosts are allowlisted through `ALLOWED_GIT_HOSTS` and credentials in URLs are rejected.

### Poll status and read reports

```bash
curl http://localhost:8000/scan/<scan_id>
curl http://localhost:8000/scan/<scan_id>/report
open "http://localhost:8000/scan/<scan_id>/report?format=html"
```

## Architecture

```text
app/
├── routers/       HTTP endpoints and content negotiation
├── services/      ingestion, static analysis, GPT review, patch checks, orchestration
├── models/        PostgreSQL entities
├── schemas/       Pydantic request/response and strict LLM contracts
├── core/          settings and async database session
├── templates/     local dashboard and report UI
└── static/        report/dashboard styles
```

Pipeline:

```text
Git URL / ZIP
      │
      ▼
Isolated workspace ── zip-slip, size and host checks
      │
      ▼
Python AST + JS/TS regex pre-filter
      │ candidates only
      ▼
GPT-5.6 structured review (strict JSON)
      │
      ├── rejected candidate
      └── confirmed finding + unified diff
                              │
                              ▼
                    git apply --check
                              │
                              ▼
                    report + patch escrow
```

## Static rules in the MVP

- SQL built with Python f-strings/string operations or JavaScript template literals/concatenation
- `eval`/`exec`/`Function` with request-like input
- common hardcoded credential patterns
- `pickle.load(s)` and unsafe `yaml.load`
- sensitive FastAPI/Flask/Express routes with no obvious auth dependency or middleware

The pre-filter intentionally favors recall. GPT-5.6 is responsible for reviewing exploitability from local evidence.

## Demo fixtures

The repository includes three tiny MIT-licensed, intentionally vulnerable fixtures so the pitch does not depend on live internet:

- `demo/archives/python-vulnerable.zip`
- `demo/archives/node-vulnerable.zip`
- `demo/archives/mixed-vulnerable.zip`

Do not deploy these applications.

## Safety controls

- no source code execution
- no dependency installation from scanned repositories
- no Git submodules
- http(s) Git host allowlist and no embedded credentials
- ZIP path traversal, expansion, file-count and size limits
- source extension and file-size filtering
- generated diff restricted to the reviewed file
- `git apply --check` only; no automatic patch application
- API keys loaded only from environment variables

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
ruff check app tests
```

The MVP uses FastAPI background tasks and one API worker. A production version should move orchestration to a durable queue, add tenant isolation, rate limits, webhook/PR delivery, richer data-flow analysis, and sandboxed patch tests.

## Build Week narrative

Sentinel was built iteratively with Codex in four working slices: ingestion, deterministic triage, GPT-5.6 review with patch escrow, and the report experience. The product thesis is simple: **AI should not silently rewrite critical code; it should produce evidence that a human can safely approve.**

## License

MIT
