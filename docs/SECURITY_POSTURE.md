# Security posture trends and remediation effectiveness

Sentinel 1.7 adds an ancestor-chain posture read model that turns persisted scan evidence into a reproducible security trend without executing repository source or introducing another model call.

## Scope

The report follows only the direct ancestors of the selected scan. Sibling branches are intentionally excluded so a branch cannot distort another branch's trend.

For every generation Sentinel records:

- confirmed, dismissed, and unreviewed candidate counts;
- verified remediations;
- raw release gate, organizational policy, exception-aware governance, and SLA state;
- policy blockers, accepted-risk findings, at-risk clocks, and overdue clocks;
- executive posture risk and residual-risk totals;
- introduced, resolved, changed, persistent, and reopened evidence.

Historical governance and SLA state are evaluated at the scan completion time. This prevents today's clock or exception state from silently rewriting an earlier point.

## Remediation effectiveness

A resolution event is created when a tracked fingerprint disappears from the next ancestor generation. Duration is measured from the beginning of the active episode to the completion time of the scan proving the disappearance.

Sentinel reports:

- mean and median time to resolution;
- resolutions within and after the immutable SLA deadline;
- SLA attainment rate for measurable episodes;
- exact fingerprint recurrence after an earlier resolution;
- currently active and currently resolved fingerprints.

A changed finding is treated as one continuous episode when deterministic comparison pairs the old and new evidence by rule, path, and nearest line. It is not incorrectly counted as a resolution.

## API

```text
GET /scan/{scan_id}/security-posture
GET /scan/{scan_id}/security-posture?format=html
```

The JSON response uses schema `sentinel-security-posture-v1` and engine `sentinel-security-posture-v1`.

## Evidence Bundle

The selected scan's complete posture trend is included in each finding Evidence Bundle. The posture engine version and the posture section are covered by the existing per-section and canonical payload SHA-256 integrity chain.

## Safety and limitations

- Repository source is never executed.
- No new GPT call is made.
- Only confirmed findings and high-confidence fail-closed unreviewed evidence participate in remediation episodes.
- Exact recurrence requires the same privacy-safe fingerprint. Semantically similar code with a different fingerprint is not claimed as recurrence.
- File renames remain explicit rather than guessed.
- Resolution time is bounded by scan cadence: Sentinel knows that evidence disappeared by the next completed scan, not the exact deployment second.
