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

## Sentinel 1.4 — Security Policy Profiles

- Added immutable, versioned security policy profiles per scan lineage.
- Added context-sensitive release thresholds for production, public, restricted-data, and critical assets.
- Added deterministic override matching and persisted policy hashes.
- Added policy preview, compliance HTML/JSON, and cross-generation compliance comparison.
- Kept the ordinary release gate authoritative and unchanged.


## Sentinel 1.5 — Security Exceptions and Risk Acceptance

- Added lineage-scoped exception requests and append-only audit events.
- Added independent approval, rejection, revocation, maximum 90-day duration, and deterministic expiry.
- Added stable finding-fingerprint, rule, and asset scopes.
- Added exception-aware governance with explicit `accepted_risk` state.
- Kept critical and fail-closed unreviewed evidence non-waivable.
- Added cross-generation exception-debt comparison and Evidence Bundle coverage.


## Sentinel 1.6

Added immutable security SLA profiles, lineage-stable finding clocks, ownership routing, overdue enforcement, debt comparison, Evidence Bundle coverage, SLA-bound exception expiry, and independently approved renewal requests.


## Sentinel 1.7 — Security Posture Trends

- Added a direct-ancestor posture timeline without mixing sibling scan branches.
- Added historical release, policy, exception, SLA, and residual-risk metrics evaluated at scan completion time.
- Added resolution episodes, mean/median remediation time, SLA attainment, and exact fingerprint recurrence.
- Preserved changed evidence as one continuous remediation episode.
- Added JSON/HTML posture reporting and Evidence Bundle integrity coverage.
- Added service, API, OpenAPI, recurrence, SLA, and regression tests.


## Sentinel 1.8 — Security Objectives and Remediation Forecasting

- Added immutable security-objective profiles and exact per-scan assignments.
- Added measurable target checks across posture, findings, policy, governance, SLA debt, remediation speed, SLA attainment, and recurrence.
- Added deterministic direct-ancestor remediation forecasting with explicit inflow, resolution capacity, required rate, projected backlog, and projected clear date.
- Added fail-closed `insufficient_history`, minimum-confidence enforcement, and reproducible scan-completion-time evaluation.
- Added JSON/HTML objective editing, preview, and reporting surfaces.
- Added initial-ingestion declarations, latest-version rescan inheritance, built-in demo objectives, and Evidence Bundle integrity coverage.
- Added service, persistence, API, OpenAPI, forecast, confidence, immutable-version, and regression tests.

## Sentinel 1.9 — Portfolio Security Governance

- Added explicit portfolios spanning independent root lineages.
- Added criticality-weighted membership and optional pinned lineage heads.
- Added fail-closed detection of missing, stale, failed, in-progress, and ambiguous evidence.
- Added immutable portfolio governance profiles with canonical SHA-256.
- Added deterministic roll-up of posture, release policy, exception governance, SLA debt, objectives, and remediation forecasts.
- Added weighted residual-risk concentration instead of hiding concentrated exposure behind an average.
- Added responsive executive portfolio UI and integrity-covered portfolio evidence export.


## Sentinel 2.0 — Continuous Security Control Plane

- Added immutable portfolio snapshots with idempotent capture keys, exact governance/control provenance, dashboard hashes, and previous-snapshot chaining.
- Added deterministic portfolio state, metric, member, evidence, governance-check, and risk transitions.
- Added immutable control-profile versions for caller-driven cadence and local alert-routing policy.
- Added deduplicated persistent alerts with acknowledgement, manual resolution, automatic clearing, and recurrence reopening.
- Added append-only per-portfolio audit events with SHA-256 previous-event chaining.
- Added explicit `never_captured`, `current`, `due`, and `overdue` schedule states without claiming a hidden scheduler.
- Added semantic configuration-drift detection against the latest immutable snapshot.
- Added responsive control-plane timeline UI and integrity-covered control-plane evidence export.
- Added service, persistence, API, OpenAPI, idempotency, alert lifecycle, hash-chain, schedule, evidence, and regression tests.
