# Security ownership and SLA enforcement

Sentinel 1.6 adds immutable remediation SLA profiles and lineage-stable finding clocks.

## Core invariants

- A clock starts when a stable finding fingerprint first appears.
- Persistent findings inherit the original start time, due date, owner, team, and SLA profile.
- Saving a new SLA profile never rewrites historical clocks. It applies to new findings in the next rescan.
- Approved risk exceptions do not pause SLA time.
- Exception expiry and renewal cannot exceed the earliest matching remediation deadline.
- Overdue debt is a separate governance blocker and can only strengthen earlier release decisions.

## Profile fields

A profile defines severity deadlines, context multipliers, an at-risk window, default ownership, escalation contacts, and deterministic overrides. Overrides may match asset ID, rule ID, repository-relative path, severity, exposure, data classification, criticality, or environment.

Default deadlines are 24 hours for critical, 168 hours for high, 720 hours for medium, and 2160 hours for low findings. Production, public, restricted-data, and critical-asset multipliers can shorten these values. The effective result is rounded up to at least one hour.

## API

```text
GET  /scan/{scan_id}/security-sla
PUT  /scan/{scan_id}/security-sla
POST /scan/{scan_id}/security-sla/preview
GET  /scan/{scan_id}/security-debt
GET  /scan/{current_scan_id}/security-debt/compare/{baseline_scan_id}
POST /scan/{scan_id}/risk-exceptions/{exception_id}/renew
```

ZIP and Git ingestion accept an optional multipart `security_sla` JSON document.

## Debt states

Each active finding is classified as:

- `on_track`: before the warning window;
- `at_risk`: inside the warning window but not overdue;
- `overdue`: past the immutable due date.

The dashboard groups debt by team and reports unassigned ownership, accepted-risk findings, upcoming deadlines, oldest age, and SLA blockers.

## Renewal control

Renewal creates a new pending exception; it does not silently extend the approved record. The successor must be independently approved. Renewal is rejected when its requested expiry exceeds the earliest matching SLA deadline.

## Limitations

SLA clocks use confirmed findings and fail-closed deterministic evidence with static confidence of at least 0.9. Fingerprints intentionally ignore line movement but include rule, normalized path, language, and sanitized evidence identity. Ownership is frozen with the first clock so a profile update cannot conceal overdue debt by reassigning it.
