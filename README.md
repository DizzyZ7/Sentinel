# Sentinel

**Sentinel is a local-first evidence-to-patch security agent powered by GPT-5.6.** It turns a suspicious code pattern into a reviewable chain of evidence: deterministic candidate, contextual verdict, constrained patch, non-executing regression proof, and explicit human decision.

> Sentinel never auto-applies a security patch and never executes scanned repository source in its default verification path.

## 60-second judge path

Requirements: Docker Desktop or Docker Engine with Compose v2.

```bash
docker compose -f compose.demo.yml up -d
```

Open `http://localhost:8000` and select **Run the 60-second security demo**.

No OpenAI API key is needed for the deterministic replay. It still runs the real ingestion, static analysis, patch validation, regression proof, persistence, attack-path, release-policy, and report code paths.

The tour deliberately shows three outcomes:

1. a SQL injection with a valid parameterized patch and `passed` regression proof;
2. a static candidate rejected as a false positive;
3. a cosmetic SQL patch that applies but leaves the vulnerability in place, fails proof, disables approval, and keeps release blocked.

For the real model path:

```bash
export OPENAI_API_KEY="..."
docker compose -f compose.demo.yml up -d
```

Then select **Run live GPT-5.6 demo**. Replay and live model calls are explicitly labelled and never conflated.

Detailed testing instructions: [`docs/JUDGE_GUIDE.md`](docs/JUDGE_GUIDE.md).

## Why this is different

Traditional SAST has deterministic evidence but often produces noise. Unconstrained AI review has context but can hallucinate vulnerabilities or unsafe fixes. Sentinel gives each layer one limited responsibility:

1. **Deterministic triage** creates candidates, not verdicts.
2. **Secret-safe GPT-5.6 review** confirms or rejects candidates through strict structured output.
3. **Patch escrow** validates a minimal unified diff without modifying the repository.
4. **Non-executing regression proof** checks whether the original deterministic signal disappeared in an isolated temporary copy.
5. **Human approval** remains mandatory.
6. **Fail-closed release policy** blocks unresolved high/critical exposure.
7. **Project Context Profiles** version real assets, production exposure, and data sensitivity without rewriting history.
8. **Risk Intelligence** maps confirmed evidence to an affected asset, business impact, residual score, and remediation plan.
9. **Security Posture Trends** measure lineage risk, remediation speed, SLA attainment, and exact recurrence.
10. **Security Objectives and Forecasting** version target states and project whether observed remediation capacity can reach them.
11. **Portfolio Security Governance** rolls independent lineages into a fail-closed executive scope.
12. **Continuous Security Control Plane** stores immutable snapshots, state transitions, local alerts, and hash-chained audit events.
13. **Evidence Bundle** exports the complete privacy-safe chain with integrity hashes.

## Architecture

```text
Git URL / ZIP
      │
      ▼
Isolated workspace
      │ zip-slip, host, file-count and size controls
      ▼
Python AST + JavaScript/TypeScript deterministic triage
      │ candidates only
      ▼
Secret-safe context sanitizer
      │ typed placeholders, preserved line numbers
      ▼
GPT-5.6 Responses API
      │ strict JSON + privacy-safe operational audit
      ├── rejected candidate
      └── confirmed finding + minimal unified diff
                              │
                              ▼
                    path/scope/syntax validation
                              │
                              ▼
                    isolated virtual patch copy
                              │
                              ▼
                    deterministic regression proof
                              │
                              ▼
                    human decision + release gate
                              │
                              ▼
                    deterministic risk intelligence
                              │
                              ▼
          technical / executive report / SARIF / Evidence Bundle
```

Sentinel remains a modular monolith: FastAPI, PostgreSQL, SQLAlchemy, Pydantic, Jinja, and isolated local artifacts. The trust model and module boundaries are documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Evidence chain

Every candidate is represented as nine stages:

```text
trust-boundary source → deterministic triage → dangerous sink
                      → affected asset → business impact
                      → GPT-5.6 verdict → patch escrow
                      → regression proof → human decision
```

Approval is structurally impossible until the proposed patch is valid and regression proof status is `passed`.

### Evidence Bundle

```bash
curl -OJ \
  http://localhost:8000/scan/<scan_id>/findings/<finding_id>/evidence-bundle
```

The bundle includes:

- scan provenance and repository-structure digest;
- sanitized static evidence;
- GPT-5.6 verdict and model-call audit;
- patch SHA-256, size, changed-line count, and sanitized diff;
- regression proof and before/after hashes;
- human decision, release gate, and Attack Graph v2;
- deterministic risk intelligence and scoring factors;
- prompt, schema, ruleset, validator, verifier, risk, policy, posture, objective, forecast, and app versions;
- SHA-256 for every top-level section and the canonical payload.

See [`docs/EVIDENCE_BUNDLE.md`](docs/EVIDENCE_BUNDLE.md).

## Static rules in the MVP

Python and JavaScript/TypeScript candidate rules cover:

- interpolated SQL;
- request-derived dynamic execution;
- hardcoded token-like values;
- unsafe Python deserialization;
- unsafe YAML loading;
- sensitive routes without obvious authorization;
- request-derived shell commands;
- request-derived filesystem paths;
- request-derived outbound URLs and SSRF candidates.

The pre-filter intentionally favors recall. GPT-5.6 is responsible for contextual exploitability review.

## Transparent evaluation

The deterministic ruleset is checked against a committed 20-case corpus:

| Metric | Current result |
| --- | ---: |
| Exact cases | 20/20 |
| Expected detections | 15 |
| False positives | 0 |
| False negatives | 0 |
| Micro precision | 100% |
| Micro recall | 100% |

These are **curated regression-fixture results**, not a claim of general-world vulnerability detection accuracy. Full case-level data is committed in [`evals/results/latest.json`](evals/results/latest.json), with methodology in [`docs/EVALUATION.md`](docs/EVALUATION.md).

Reproduce it:

```bash
python -m scripts.run_evals \
  --output evals/results/latest.json \
  --markdown docs/EVALUATION.md \
  --fail-on-regression
```

CI fails if any expected rule disappears or any unexpected finding is introduced.

## Baselines and no-new-risk policy

Sentinel can rescan a preserved source and compare the new result with a completed baseline:

```bash
curl -X POST http://localhost:8000/scan/<baseline_scan_id>/rescan
curl 'http://localhost:8000/scan/<current_scan_id>/compare/<baseline_scan_id>?format=html'
```

Findings are matched through a privacy-safe fingerprint rather than line number, so moved evidence stays persistent. The comparison classifies introduced, resolved, changed, and persistent findings and evaluates a separate **delta gate**. This lets teams enforce “no new high/critical security debt” while legacy exposure remains visible in the ordinary full gate. A newly introduced finding stops blocking the delta gate only after its patch is validated, regression proof passes, and a human approves it.

The judge view includes **Start rescan** and automatically opens the delta report when the new scan completes. Full semantics and limitations are documented in [`docs/BASELINE_COMPARISON.md`](docs/BASELINE_COMPARISON.md).

The judge and delta views also expose the persisted lineage and let a reviewer select any earlier completed scan in the same history. CI can evaluate the immediate parent automatically:

```bash
sentinel-check-delta --current-scan-id <current_scan_id>
```

The CLI exits `0` when the delta passes, `1` for a blocking security regression, and `2` for operational failure. Full lineage and CI semantics are documented in [`docs/LINEAGE_AND_CI.md`](docs/LINEAGE_AND_CI.md).


## Risk intelligence and executive decision

Sentinel 1.2 turns each confirmed finding into a reproducible business-risk record. GPT-5.6 supplies the contextual verdict, while Sentinel calculates the score locally from technical severity, exploitability, exposure, asset importance, confidence, and verified remediation state.

```bash
curl http://localhost:8000/scan/<scan_id>/risk-intelligence
curl 'http://localhost:8000/scan/<scan_id>/executive-report?format=html'
```

The executive report prioritizes affected assets, public attack surfaces, residual risk, estimated effort, and ordered remediation actions. The business score never overrides the ordinary fail-closed release gate. Full semantics and limitations are documented in [`docs/RISK_INTELLIGENCE.md`](docs/RISK_INTELLIGENCE.md).

## Project Context Profiles

Sentinel 1.3 can attach an immutable, versioned project profile to every scan. Profiles declare production environment, internet exposure, compliance frameworks, and path-matched assets with criticality and data classification.

```bash
curl http://localhost:8000/scan/<scan_id>/project-context
curl -X POST http://localhost:8000/scan/<scan_id>/project-context/preview \
  -H 'Content-Type: application/json' \
  --data @project-context.json
```

Saving a new profile version never changes historical scores. The next rescan inherits the latest version, while the current scan retains its assigned profile and SHA-256. See [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md).

## API highlights

```text
POST /scan/repo
POST /scan/demo?mode=replay
POST /scan/demo?mode=live
POST /scan/{baseline_scan_id}/rescan
GET  /scan/{current_scan_id}/compare/{baseline_scan_id}
GET  /scan/{scan_id}/lineage
GET  /scan/{current_scan_id}/ci-gate
GET  /scan/{scan_id}/project-context
PUT  /scan/{scan_id}/project-context
POST /scan/{scan_id}/project-context/preview
GET  /scan/{scan_id}/risk-intelligence
GET  /scan/{scan_id}/executive-report
GET  /scan/{scan_id}/findings/{finding_id}/risk-intelligence
GET  /scan/{scan_id}/risk-exceptions
POST /scan/{scan_id}/risk-exceptions
GET  /scan/{scan_id}/exception-aware-compliance
GET  /scan/{scan_id}/security-posture
GET  /scan/{scan_id}/security-objectives
PUT  /scan/{scan_id}/security-objectives
POST /scan/{scan_id}/security-objectives/preview
GET  /scan/{scan_id}/objective-report
GET  /scan/{current_scan_id}/exception-debt/compare/{baseline_scan_id}
GET  /scan/{scan_id}/progress
GET  /scan/{scan_id}/events
GET  /scan/{scan_id}/report
GET  /scan/{scan_id}/attack-paths
GET  /scan/{scan_id}/gate
GET  /scan/{scan_id}/verifications
GET  /scan/{scan_id}/llm-reviews
GET  /scan/{scan_id}/findings/{finding_id}/patch
POST /scan/{scan_id}/findings/{finding_id}/decision
GET  /scan/{scan_id}/findings/{finding_id}/evidence-bundle
GET  /portfolios
POST /portfolios
GET  /portfolios/{portfolio_id}
PUT  /portfolios/{portfolio_id}
POST /portfolios/{portfolio_id}/members
DELETE /portfolios/{portfolio_id}/members/{root_scan_id}
GET  /portfolios/{portfolio_id}/governance
PUT  /portfolios/{portfolio_id}/governance
GET  /portfolios/{portfolio_id}/dashboard
GET  /portfolios/{portfolio_id}/evidence
GET  /portfolios/{portfolio_id}/control-plane
PUT  /portfolios/{portfolio_id}/control-plane
GET  /portfolios/{portfolio_id}/control-plane/status
GET  /portfolios/{portfolio_id}/control-plane/verify
POST /portfolios/{portfolio_id}/snapshots
GET  /portfolios/{portfolio_id}/snapshots
GET  /portfolios/{portfolio_id}/snapshots/{snapshot_id}
GET  /portfolios/{portfolio_id}/timeline
GET  /portfolios/{portfolio_id}/alerts
POST /portfolios/{portfolio_id}/alerts/{alert_id}/acknowledge
POST /portfolios/{portfolio_id}/alerts/{alert_id}/resolve
GET  /portfolios/{portfolio_id}/audit-events
GET  /portfolios/{portfolio_id}/control-plane/evidence
```

OpenAPI is available at `http://localhost:8000/docs`.

## Safety controls

- scanned repository source is not imported or executed;
- repository dependencies are not installed;
- Git submodules are disabled;
- Git hosts are allowlisted and embedded credentials are rejected;
- ZIP traversal, expansion, file-count, and size limits are enforced;
- source extensions and individual file sizes are filtered;
- repository comments and strings are treated as untrusted model data;
- secret-like values are redacted before external transmission and evidence export;
- original secrets are not stored in LLM audit rows;
- generated diffs are restricted to the reviewed file;
- rename, mode-change, binary, oversized, and multi-file patches are rejected;
- `git apply --check` and Python syntax validation run before proof;
- the original repository is never automatically modified;
- partial, failed, skipped, and inconclusive states remain fail-closed.

## Supported platforms

The prebuilt container targets `linux/amd64` and `linux/arm64` and runs through Docker Desktop on Windows/macOS or Docker Engine on Linux.

Source development requires:

- Python 3.12+;
- Git;
- PostgreSQL 17 through Docker Compose.

## Source development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
ruff check app tests scripts
python -m scripts.run_evals --fail-on-regression
```

Source-build Docker path:

```bash
cp .env.example .env
# Add OPENAI_API_KEY for live GPT-5.6 review.
docker compose up --build -d
```

Without an API key, ordinary repository ingestion and deterministic analysis still run; candidates are marked as skipped for deep review. The built-in deterministic judge replay remains available.

## How GPT-5.6 is used

GPT-5.6 is an evidence-bound contextual reviewer. It receives a bounded, secret-sanitized code window and must return strict JSON containing:

- confirmed or rejected verdict;
- severity, CVSS, confidence, and CWE;
- explanation and attack scenario;
- remediation recommendation;
- minimal unified diff.

GPT-5.6 cannot apply patches, grant approval, or override release policy. Every model call records response ID, prompt/schema versions, latency, retries, usage, context digest, and redaction metadata.

## How Codex accelerated the build

Sentinel was developed with Codex as a sequence of small reviewed vertical slices. Codex helped:

- design the trust boundaries and modular-monolith architecture;
- implement analyzers, strict schemas, patch escrow, regression proof, and evidence export;
- generate adversarial fixtures and application-level golden tests;
- refactor duplicated policy logic and harden failure states;
- improve the judge workflow and delivery path;
- verify each merge through pytest, Ruff, Docker, and GitHub Actions.

Key decisions and the implementation timeline are documented in [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md). The repository's merged pull requests provide timestamped evidence of the work completed during Build Week.

## Submission materials

- [`docs/JUDGE_GUIDE.md`](docs/JUDGE_GUIDE.md)
- [`docs/VIDEO_SCRIPT.md`](docs/VIDEO_SCRIPT.md)
- [`docs/DEVPOST_SUBMISSION.md`](docs/DEVPOST_SUBMISSION.md)
- [`docs/BUILD_LOG.md`](docs/BUILD_LOG.md)


## Final submission preflight

Sentinel includes a repository-side readiness checker that verifies version alignment, required judge files, committed eval results, prebuilt-image configuration, multi-architecture publishing, and release-tree hygiene.

```bash
python -m scripts.check_release
```

The four external steps—anonymous GHCR access, public video URL, Codex Session ID, and final Devpost review—remain explicitly manual. After completing them, run the strict check described in [`docs/SUBMISSION_CHECKLIST.md`](docs/SUBMISSION_CHECKLIST.md).

Anonymous GHCR access can be probed without Docker credentials:

```bash
python -m scripts.check_public_image
```

## License

MIT

## Security Policy Profiles

Sentinel 1.4 versions organizational release rules alongside project context. Policies can strengthen thresholds for production, public, restricted-data, or critical assets and require validated patches, passed proof, and explicit human approval.

```bash
curl http://localhost:8000/scan/<scan_id>/security-policy
curl 'http://localhost:8000/scan/<scan_id>/policy-compliance?format=html'
```

Saving a policy creates an immutable version for the next rescan. The current scan retains its assigned policy hash, and compliance changes can be compared across lineage generations. See [`docs/SECURITY_POLICY.md`](docs/SECURITY_POLICY.md).


## Security Exceptions and Risk Acceptance

Sentinel 1.5 records temporary, scoped risk acceptance without deleting evidence or rewriting the raw release gate. Requests require a risk owner, justification, expiry, maximum severity, and independent approval. Critical and fail-closed unreviewed findings remain non-waivable.

```bash
curl 'http://localhost:8000/scan/<scan_id>/risk-exceptions?format=html'
curl 'http://localhost:8000/scan/<scan_id>/exception-aware-compliance?format=html'
```

Approved exceptions produce a separate `accepted_risk` governance state, automatically stop applying at expiry or revocation, and are included in the Evidence Bundle integrity chain. See [`docs/SECURITY_EXCEPTIONS.md`](docs/SECURITY_EXCEPTIONS.md).


## Security Ownership and SLA Enforcement

Sentinel 1.6 assigns lineage-stable remediation clocks to confirmed and fail-closed findings. Severity deadlines are shortened by production exposure, public assets, restricted data, criticality, and deterministic overrides.

```bash
curl 'http://localhost:8000/scan/<scan_id>/security-sla?format=html'
curl 'http://localhost:8000/scan/<scan_id>/security-debt?format=html'
```

Persistent findings keep their original owner and deadline across rescans. Exceptions do not pause the clock, and renewal cannot exceed the remediation deadline. See [`docs/SECURITY_SLA.md`](docs/SECURITY_SLA.md).


## Security Posture Trends and Remediation Effectiveness

Sentinel 1.7 turns immutable lineage evidence into an ancestor-chain security trend. It reports posture risk, release and governance state, policy blockers, accepted risk, SLA debt, introduced/resolved/changed evidence, verified remediation speed, SLA attainment, and exact fingerprint recurrence.

```bash
curl http://localhost:8000/scan/<scan_id>/security-posture
curl 'http://localhost:8000/scan/<scan_id>/security-posture?format=html'
```

Historical points are evaluated at their own completion time, sibling branches are excluded, changed evidence remains one continuous remediation episode, and the complete trend is integrity-covered inside the Evidence Bundle. See [`docs/SECURITY_POSTURE.md`](docs/SECURITY_POSTURE.md).


## Security Objectives and Remediation Forecasting

Sentinel 1.8 versions the measurable security state a lineage is expected to reach. Objectives can constrain posture score, confirmed exposure, policy blockers, overdue SLA debt, accepted risk, remediation time, SLA attainment, recurrence, and required governance states.

```bash
curl 'http://localhost:8000/scan/<scan_id>/security-objectives?format=html'
curl 'http://localhost:8000/scan/<scan_id>/objective-report?format=html'
```

The forecast uses only positive-duration intervals in the selected scan's direct ancestor chain. It exposes observed inflow and resolution capacity, required resolution rate, projected active backlog, explicit confidence, and `insufficient_history` instead of fabricating certainty. Historical reports are evaluated at scan completion time so they remain reproducible.

Initial ingestion accepts an optional multipart `security_objectives` JSON document. Saving a new version affects only the next rescan; the current scan retains its exact assigned objective SHA-256. The objective report and both engine versions are integrity-covered inside the Evidence Bundle. See [`docs/SECURITY_OBJECTIVES.md`](docs/SECURITY_OBJECTIVES.md).

## Portfolio Security Governance

Sentinel 1.9 governs multiple independent root lineages without merging their histories. Portfolios explicitly select lineage roots, business criticality, and optional pinned heads. Ambiguous sibling heads, missing evidence, stale scans, failed runs, and in-progress scans remain visible and fail closed.

```bash
curl http://localhost:8000/portfolios
curl 'http://localhost:8000/portfolios/<portfolio_id>/dashboard?format=html'
curl http://localhost:8000/portfolios/<portfolio_id>/evidence
```

The dashboard rolls up posture, policy, exception-aware governance, SLA debt, objectives, forecasts, and criticality-weighted residual-risk concentration. Governance profiles are immutable and versioned by canonical SHA-256. The portfolio evidence export receives per-section and canonical payload integrity hashes. See [`docs/PORTFOLIO_GOVERNANCE.md`](docs/PORTFOLIO_GOVERNANCE.md).


## Continuous Security Control Plane

Sentinel 2.0 converts query-time portfolio governance into an explicit operational record. Each capture stores an immutable dashboard, its governance/control versions, a previous-snapshot hash, deterministic metric and member transitions, and a snapshot SHA-256.

```bash
curl -X POST http://localhost:8000/portfolios/<portfolio_id>/snapshots \
  -H 'Content-Type: application/json' \
  -d '{"source":"scheduled","actor":"nightly-ci","idempotency_key":"security-2026-07-19"}'
curl 'http://localhost:8000/portfolios/<portfolio_id>/timeline?format=html'
curl -OJ http://localhost:8000/portfolios/<portfolio_id>/control-plane/evidence
```

Cadence is caller-driven: Sentinel reports `current`, `due`, `overdue`, or `never_captured` but does not pretend to run a hidden scheduler. Persistent conditions are deduplicated into a local alert queue, automatically resolve when cleared, and reopen on recurrence. Control-profile changes, snapshots, and alert lifecycle actions are recorded in an append-only SHA-256 audit chain. No external alert transport is invoked. See [`docs/CONTROL_PLANE.md`](docs/CONTROL_PLANE.md).
