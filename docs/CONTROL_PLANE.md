# Continuous Security Control Plane

Sentinel 2.0 adds a deterministic operational layer above portfolio governance. It records what the portfolio looked like at an explicit point in time, explains how that state changed, routes local alerts, and preserves every control-plane action in a hash-chained audit stream.

The control plane does not run a hidden scheduler. Snapshot cadence is policy data. A caller such as CI, cron, an operator, or another local orchestrator explicitly invokes the capture endpoint. Sentinel reports whether the next capture is current, due, overdue, or has never occurred.

## Immutable control profiles

Each portfolio receives versioned `PortfolioControlProfile` rows. The canonical document controls:

- snapshot cadence in hours;
- alerts for `at_risk`, `blocked`, and `insufficient_evidence` portfolio states;
- state-regression and optional recovery events;
- member-blocked and evidence-degradation conditions;
- SLA overdue debt, missed objectives, off-track forecasts, and missed governance checks;
- automatic resolution when a persistent condition clears;
- local route labels.

Saving an identical document reuses the latest version. A changed document creates a new immutable version and audit event with canonical SHA-256.

Route labels are local queue destinations such as `local-security-queue`, `soc`, or `engineering`. Sentinel 2.0 does not perform external webhook, email, or chat delivery and therefore does not claim delivery it cannot prove.

## Snapshot capture

```http
POST /portfolios/{portfolio_id}/snapshots
```

Example body:

```json
{
  "source": "scheduled",
  "actor": "nightly-ci",
  "idempotency_key": "security-2026-07-19"
}
```

The optional idempotency key is unique within the portfolio. Repeating the same request returns the original snapshot instead of creating duplicate evidence, alerts, or audit events.

Every `PortfolioSnapshot` stores:

- monotonically increasing portfolio sequence;
- exact capture time, source, actor, and idempotency key;
- complete portfolio dashboard JSON;
- exact governance and control-profile IDs, versions, and SHA-256 values;
- previous snapshot ID and SHA-256;
- dashboard SHA-256 and snapshot SHA-256;
- deterministic transition from the previous snapshot.

Snapshots are append-only through the public API. No update or delete endpoint exists.

## Deterministic transitions

The transition engine reports:

- previous and current portfolio states;
- `initial`, `improved`, `unchanged`, or `degraded` direction;
- numeric deltas for exposure, SLA debt, objectives, forecasts, posture, and residual risk;
- added, removed, and changed members;
- readiness, evidence, selected-head, criticality, release, policy, governance, objective, and forecast changes;
- newly missed and cleared governance checks.

State ordering is explicit and fail closed:

```text
passed < at_risk < blocked < insufficient_evidence
```

This ordering is used only to describe transition direction. It never weakens the underlying portfolio or lineage decision.

## Local alert routing

Persistent conditions use stable keys. Examples:

```text
portfolio:blocked
portfolio:insufficient_evidence
member:<root_scan_id>:blocked
member:<root_scan_id>:evidence:stale
portfolio:sla_overdue
governance:<check_key>
```

When an active condition first appears, Sentinel opens one local alert. Repeated snapshots update its occurrence count rather than producing duplicate queue records. When the condition clears, the alert can be automatically resolved. If it later returns, the same alert is reopened and the lifecycle is recorded in the audit chain.

Transient state-regression or recovery alerts use snapshot-scoped event keys and are never mistaken for persistent conditions.

Alert states are:

- `open`;
- `acknowledged` with actor and timestamp;
- `resolved` with actor, timestamp, and reason.

## Hash-chained audit stream

`PortfolioAuditEvent` is append-only and portfolio-scoped. Each event includes the previous event SHA-256 before its own canonical digest is calculated.

Recorded events include:

- control profile creation and version changes;
- snapshot capture;
- alert open, reopen, acknowledge, manual resolve, and automatic resolve.

The first event has no previous hash. Every following event must reference the immediately preceding digest. This detects deletion, insertion, reordering, or modification inside an exported chain. It is an integrity chain, not a third-party identity signature.

## Schedule status

```http
GET /portfolios/{portfolio_id}/control-plane/status
```

The response reports:

- configured cadence;
- latest snapshot and state;
- next due time and snapshot age;
- `never_captured`, `current`, `due`, or `overdue` schedule state;
- whether portfolio membership, metadata, governance, or control policy changed since the latest snapshot;
- open, acknowledged, and resolved alert counts;
- an explicit `caller_driven: true` execution boundary.

Configuration drift is determined from semantic portfolio membership and metadata plus exact governance/control hashes, not from an unreliable wall-clock approximation.

## API

```text
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

The timeline supports responsive HTML through `?format=html` or `Accept: text/html`.

## Control-plane evidence

`sentinel-control-plane-evidence-v1` includes:

- app, portfolio, control-plane, alert, and audit-chain engine versions;
- exact control profile history;
- schedule status;
- all immutable snapshot details and snapshot hashes;
- current alert lifecycle records;
- audit events in ascending sequence;
- per-section SHA-256;
- canonical payload SHA-256.

The export is deterministic for the same stored state and explicit `generated_at`. Schedule age is part of the evidence boundary, so a later export can legitimately differ even when the immutable snapshot chain has not changed.

## Safety boundaries

Sentinel 2.0:

- makes no new GPT call;
- executes no repository source;
- installs no repository dependency;
- applies no patch;
- sends no external alert;
- creates no hidden background task;
- cannot approve remediation or bypass lineage/portfolio governance;
- exposes missing, stale, failed, in-progress, and ambiguous evidence instead of suppressing it.
