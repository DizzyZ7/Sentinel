# Sentinel Build Week engineering log

Sentinel was developed as a sequence of reviewable vertical slices rather than as one large generated code drop. Codex was used to explore designs, implement and refactor modules, construct adversarial tests, review diffs, and drive every slice through local and GitHub CI verification.

## Product thesis

Traditional SAST has deterministic evidence but often creates noise. Unconstrained AI review has context but can hallucinate or propose unsafe changes. Sentinel combines both and requires a human decision after a validated, regression-proven patch.

## Major slices

### 0.3 — attack paths and release policy

- seven-stage reasoning graph
- fail-closed release gate
- SARIF export
- explicit human approval boundary

### 0.4 — non-executing regression proof

- applies patches only to an isolated temporary copy
- re-runs the same deterministic rule around the changed hunk
- records before/after digests and `source_executed=false`
- blocks approval unless proof status is `passed`

### 0.5 — secret-safe GPT-5.6 auditing

- removes credential-like values before model transmission
- stores response ID, model, prompt/schema versions, retries, latency, usage, and redaction metadata
- never stores the original secret value in the audit row

### 0.6 — golden judge path

- one-click deterministic replay and separate live GPT-5.6 mode
- append-only scan progress events
- full application-level golden test covering ingestion through release policy
- three deliberately different judge outcomes

### 0.7 — portable evidence and prebuilt delivery

- self-verifying Evidence Bundle with per-section and payload SHA-256
- hardened read-only demo container
- multi-architecture GHCR publication workflow
- CI verification that the judge fixture is packaged in the image

### 0.8 — measurable evaluation and submission readiness

- 20-case transparent deterministic corpus
- TP/FP/FN, precision, recall, and exact-case metrics
- CI regression gate and downloadable result artifact
- judge guide, timed video script, and Devpost-ready project copy


### 0.9 — judge decision view and submission preflight

- focused read-only judge decision surface
- automated release-readiness artifact
- anonymous GHCR verification workflow
- final recording and submission guides

### 1.0 — baseline deltas and incremental security policy

- stable finding fingerprints independent of line movement
- introduced, resolved, changed, and persistent classifications
- ordinary full gate plus a no-new-risk delta gate
- ZIP/Git rescan workflow through the unchanged security pipeline
- responsive HTML delta report and judge-view rescan action

### 1.1 — persistent lineage and CI regression contract

- separate lineage table for root, parent, and generation without altering historical scan rows
- baseline selectors in judge and delta views
- same-lineage CI endpoint with HTTP and header exit signals
- packaged CLI with stable exit codes 0, 1, and 2
- fail-closed parent-baseline resolution and regression tests

## Key engineering decisions made with Codex

1. Keep a modular monolith instead of adding premature microservices.
2. Treat static rules as candidate generators, not final verdicts.
3. Never execute scanned repository code in the default verification path.
4. Never automatically apply an AI-generated patch.
5. Sanitize model context and export data independently.
6. Make failure and inconclusive states block release rather than silently pass.
7. Separate deterministic replay from live GPT-5.6 so the demo remains honest and reliable.
8. Publish evidence and limitations instead of claiming unsupported benchmark performance.

## Verification discipline

Every merged product slice was required to pass:

- pytest;
- Ruff;
- Python compilation;
- Docker build;
- relevant application and API smoke tests;
- an independent GitHub Actions run before merge.

## Submission evidence

Before submitting, add the primary Codex `/feedback` Session ID to the Devpost form. Commit history and merged pull requests document the implementation timeline and the features added during Build Week.


### 1.2 — deterministic security intelligence

- one-to-one persisted risk intelligence for confirmed findings
- transparent inherent and residual scoring factors
- affected-asset, business-impact, priority, effort, and remediation-plan model
- executive JSON and responsive HTML report
- Attack Graph v2 with asset and impact stages
- Evidence Bundle integrity coverage for the risk section and engine version


## Sentinel 1.3 — Project Context Profiles

- Added immutable profile versions and per-scan assignments.
- Added declared asset catalog with repository-relative path matching.
- Added deterministic criticality, environment, exposure, and data-classification overrides.
- Added initial-scan profile ingestion, automatic rescan inheritance, and built-in demo context.
- Added JSON/HTML profile history, safe preview, and future-version editing.
- Added context version/hash/source to Risk Intelligence and Executive Reports.
