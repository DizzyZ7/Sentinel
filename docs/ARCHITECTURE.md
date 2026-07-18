# Sentinel architecture

## Architectural style

Sentinel is a local-first modular monolith. FastAPI exposes the API and report UI, PostgreSQL stores scan state and audit metadata, and a local artifact store keeps immutable source snapshots, patch proposals, SARIF, and regression proofs.

The design optimizes for a small trusted deployment surface, reproducible evidence, and explicit human control. It deliberately avoids executing repository source or automatically applying model-generated changes.

## System context

```text
User / CI
    |
    v
FastAPI API + report UI
    |
    v
Scan orchestration
    |
    +--> source ingestion and isolation
    +--> deterministic Python / JS / TS analysis
    +--> context sanitization
    +--> GPT-5.6 structured review
    +--> patch escrow and validation
    +--> non-executing regression proof
    +--> human decision
    +--> fail-closed release policy
    |
    +--> PostgreSQL metadata
    +--> local immutable artifacts
```

## Trust boundaries

1. Uploaded archives, cloned repositories, filenames, source text, comments, strings, and generated patches are untrusted input.
2. Repository source is never imported or executed by the default pipeline.
3. Source-borne text is never treated as an instruction to GPT-5.6.
4. Secret-like values are replaced with typed placeholders before external model transmission.
5. Original secret values are not stored in LLM audit records.
6. Model output is data, not an action. It must pass strict schema validation and patch validation.
7. Human approval records intent but never modifies the scanned repository.
8. Release decisions fail closed when review or proof is incomplete.

## Pipeline

```text
Git URL / ZIP
    |
    v
Isolated repository snapshot
    |
    v
Deterministic candidates
    |
    v
50-line evidence context
    |
    v
ContextSanitizer
    |  typed placeholders + redaction metadata
    v
GPT-5.6 Responses API
    |  strict Pydantic JSON schema
    v
LLMReviewRun audit record
    |  model, response id, versions, latency, retries, usage
    v
Confirmed finding + minimal unified diff
    |
    v
Patch validator
    |  one expected file, size limits, git apply --check, syntax checks
    v
Regression verifier
    |  isolated one-file copy, before/after static signal, SHA-256
    v
Human decision + release gate
```

## Modules

```text
app/
├── core/       configuration and async database lifecycle
├── models/     persisted scan, finding, decision, proof, and audit facts
├── routers/    HTTP transport and content negotiation
├── schemas/    API DTOs and strict model-output contracts
├── services/   ingestion, analysis, review, validation, proof, policy
├── templates/  local report and dashboard
└── static/     report styles
```

The service layer is split by capability rather than framework endpoint. Routers should not contain security-analysis rules or model prompts.

## Primary entities

### Scan

Owns the repository snapshot, lifecycle, aggregate risk score, and findings.

### Finding

Represents one deterministic candidate and the evidence accumulated around it:

```text
static candidate
  + GPT-5.6 verdict
  + patch proposal
  + patch validation
  + regression proof
  + human decision
```

### LLMReviewRun

One auditable model review per finding. It stores operational metadata, not source context or secret values:

- model and response ID;
- prompt and schema versions;
- SHA-256 of the sanitized context;
- typed redaction counts and line numbers;
- retries, latency, and token usage;
- terminal status and sanitized error.

### RegressionVerification

A non-executing structural proof. It applies a validated patch only to a temporary copy and records whether the original deterministic source-to-sink candidate disappears.

### ReviewDecision

An explicit human approval or rejection. Approval is permitted only for a validated patch with a passed regression proof.

## Approval invariant

A finding may be approved only when all of the following are true:

```text
confirmed by GPT-5.6
AND patch_valid = true
AND regression_verification.status = passed
AND human decision = approved
```

No API or UI path may bypass this invariant.

## Audit and privacy

Sentinel sends only the minimum local evidence needed for one candidate. Before transmission, `ContextSanitizer` redacts credential assignments, private keys, common provider tokens, bearer tokens, JWTs, and credentials embedded in connection strings.

Placeholders retain evidence structure and line numbers, for example:

```text
OPENAI_API_KEY = "<REDACTED_SECRET_1:CREDENTIAL_ASSIGNMENT>"
```

Audit records contain the redaction type, count, and affected lines but never the original value. The sanitized context is identified by SHA-256 for reproducibility without storing the context itself.

## Deployment model

The contest deployment uses one API process, PostgreSQL, and a persistent local artifact volume. Scan work currently runs through FastAPI background tasks to keep the demo installation small.

A production evolution should introduce a durable PostgreSQL-backed job queue and a separate worker while preserving the same application contracts. Microservices are not required until workload isolation or independent scaling justifies the operational cost.

## Versioned boundaries

Security-sensitive components are versioned independently:

- static ruleset;
- GPT review prompt;
- structured-output schema;
- patch validator;
- regression verifier;
- release policy.

Every exported evidence bundle should eventually include all component versions so a result can be reproduced and compared across releases.


## Observable orchestration

`ScanEvent` is an append-only operational timeline. It keeps transient progress outside the `Scan` aggregate so new stages can be introduced without repeatedly altering the core scan table. The dedicated progress API reads the latest event, while `/scan/{scan_id}/events` exposes the complete timeline for the dashboard, debugging, and the competition demo.

Current stages are `queued`, `ingesting`, `indexing`, `prefiltering`, `reviewing`, `finalizing`, `completed`, and `failed`. A degraded event is emitted when deep review is unavailable; deterministic evidence is preserved and policy remains fail-closed.

## Demo boundary

The built-in replay uses the same ingestion, analyzer, patch validator, regression verifier, persistence, reporting, and release-policy code as an ordinary scan. Only the reviewer adapter is replaced by `DemoReviewer`, and its audit records are explicitly identified as `sentinel-deterministic-demo-replay`. Live demo mode uses the ordinary GPT-5.6 gateway. This prevents a deterministic product tour from being misrepresented as an external model call.

## Golden path verification

The golden end-to-end test runs the packaged judge fixture through a temporary SQLite database and the real application pipeline. It verifies three outcomes in one execution: confirmed and proof-passing remediation, false-positive rejection, and a validated but regression-failing patch. It also asserts the fail-closed release gate and the persisted progress timeline.


## Baseline comparison boundary

Scan comparison is a derived read model rather than a new persistence aggregate. `ComparisonService` consumes two completed `Scan` aggregates and their persisted findings, then emits introduced, resolved, changed, and persistent evidence. No repository source is executed and no model call is required.

Exact matching uses a SHA-256 fingerprint over rule ID, normalized path, language, and normalized evidence. Remaining findings with the same rule and path are paired by nearest line location. This keeps line movement stable without pretending to infer file renames or arbitrary semantic equivalence.

The full gate and delta gate intentionally answer different questions:

```text
full gate  → is all current in-scope exposure remediated?
delta gate → did this change introduce or materially alter unresolved in-scope exposure?
```

A rescan always creates a new isolated workspace and runs the ordinary ingestion-to-policy pipeline. Preserved ZIP input can only be copied from within the configured scan root.


## Persistent scan lineage

`ScanLineage` is a small persistence aggregate separate from `Scan`. It stores `scan_id`, `parent_scan_id`, `root_scan_id`, and `generation`, allowing branches and repeated rescans without modifying the original scan schema. New root scans are registered at creation; pre-1.1 scans are registered lazily when first used as a rescan baseline.

The lineage read model exposes only scan metadata and eligibility, not source snippets. The CI gate resolves the immediate parent by default and rejects an explicit baseline outside the same earlier completed lineage. Security regression, operational error, and successful evaluation remain distinct states.


## Deterministic risk intelligence boundary

`RiskIntelligence` is a one-to-one persistence aggregate for confirmed findings. It translates the existing contextual verdict into asset, exposure, impact, scoring factors, residual risk, priority, and remediation guidance. The calculation is local and versioned; it does not introduce another model call or execute repository source.

Inherent risk is calculated from technical severity, exploitability, exposure, asset importance, and review confidence. Residual risk applies a transparent multiplier based on patch validation, non-executing regression proof, and explicit human approval. The ordinary release gate remains authoritative and cannot be bypassed by an executive score.

Attack Graph v2 adds affected-asset and business-impact nodes before the existing verdict, patch, proof, and human-decision chain. The executive report and Evidence Bundle consume the same persisted scoring record.


## Project context boundary

`ProjectContextProfile` stores immutable JSON documents per lineage root, while `ScanContextAssignment` binds each scan to one exact profile version. Risk Intelligence receives a read-only snapshot and persists the profile version, context hash, resolution source, and matched asset ID inside its scoring factors. Profile updates apply only to future rescans; preview uses an in-memory snapshot and never rewrites evidence.

## Security policy layer

The security-policy module is a deterministic decision layer above the ordinary release gate. It reads persisted finding state plus the scan-assigned project context and policy versions. It never executes repository source, mutates findings, approves remediation, or weakens the base gate. Profiles and scan assignments are stored separately so historical compliance remains reproducible.


## Risk-exception governance layer

The risk-exception module is an additive governance boundary above raw security-policy compliance. It persists lineage-scoped exception requests and append-only lifecycle events, resolves stable finding/rule/asset scopes, and calculates a separate `passed`, `accepted_risk`, or `blocked` decision. Raw findings, the ordinary release gate, policy compliance, patch proof, and human remediation decisions are never mutated. Critical and fail-closed unreviewed evidence are non-waivable.
