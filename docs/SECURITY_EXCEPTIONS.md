# Sentinel Security Exceptions and Risk Acceptance

Sentinel 1.5 adds a governance layer for temporary, accountable risk acceptance. An exception never deletes a finding, changes GPT evidence, marks a patch as valid, or rewrites the raw release gate. It records why a release is proceeding despite a known policy blocker.

## Lifecycle

Every exception is scoped to one scan lineage and moves through an append-only audit trail:

```text
requested -> approved -> expired
          -> rejected
approved  -> revoked
```

The current row stores the effective lifecycle fields for fast evaluation. `risk_exception_events` stores the actor, reason, timestamp, and metadata for every request, decision, and revocation.

## Mandatory controls

An exception requires:

- a specific finding, rule, or project-context asset target;
- a written justification of at least 20 characters;
- a named risk owner;
- a named requester;
- an explicit maximum severity of low, medium, or high;
- an expiry between one hour and 90 days;
- an independent approver whose identity differs from the requester.

There are no indefinite exceptions. Expiry is calculated from the stored timestamp and becomes effective automatically without a background job.

## Stable scope

Finding-scoped requests are converted to Sentinel's stable finding fingerprint: rule ID, normalized repository path, language, and normalized evidence snippet. The exception can therefore follow the same finding across line movement and rescan generations.

Rule and asset exceptions remain lineage-wide. Matching uses the assigned project-context profile for each evaluated scan.

## Non-waivable evidence

The governance layer refuses to waive:

- critical findings;
- high-confidence deterministic evidence whose deep review failed, was skipped, or remains pending.

This prevents a governance record from turning missing security evidence into a release approval.

## Decision surfaces

The raw organizational policy result remains available at:

```http
GET /scan/{scan_id}/policy-compliance
```

The separate exception-aware decision is available at:

```http
GET /scan/{scan_id}/exception-aware-compliance
```

Its states are:

- `passed`: no raw blockers exist;
- `accepted_risk`: every raw blocker is covered by an active approved exception;
- `blocked`: at least one blocker is uncovered or non-waivable.

`accepted_risk` does not mean the technical exposure is fixed. It means the organization explicitly owns the temporary residual risk.

## API

```http
GET  /scan/{scan_id}/risk-exceptions
POST /scan/{scan_id}/risk-exceptions
POST /scan/{scan_id}/risk-exceptions/{exception_id}/decision
POST /scan/{scan_id}/risk-exceptions/{exception_id}/revoke
GET  /scan/{scan_id}/exception-aware-compliance
GET  /scan/{current_scan_id}/exception-debt/compare/{baseline_scan_id}
```

The HTML register supports requesting, approving, rejecting, and revoking exceptions. The governance report keeps accepted findings visually separate from passed findings.

## Exception debt comparison

Cross-generation comparison evaluates active exception scopes as of each scan's completion timestamp. It reports introduced, resolved, and persistent exception scopes plus the accepted-finding count at each generation.

This historical snapshot avoids applying a later approval retroactively to an earlier scan.

## Evidence Bundle

The Evidence Bundle includes:

- the risk-exception engine version;
- the raw policy-compliance result;
- the exception-aware governance result;
- applied exception identifiers, scopes, and expiry timestamps;
- non-waivable reasons;
- SHA-256 coverage through the normal per-section and canonical payload hashes.

The full exception register remains in PostgreSQL. The bundle contains the decision state needed to explain the exported finding at generation time.

## Limitations

- Identity strings are application-level actor labels, not yet signed organizational identities.
- Expiry is deterministic on read; no separate notification scheduler is included.
- Exception scope is lineage-local and does not span multiple repositories.
- Critical findings are intentionally non-waivable in Sentinel 1.5.
