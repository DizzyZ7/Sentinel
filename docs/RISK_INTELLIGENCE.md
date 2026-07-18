# Sentinel Risk Intelligence

Sentinel 1.2 converts confirmed technical findings into a deterministic business-risk model without weakening the existing release gate.

## Trust boundary

GPT-5.6 supplies contextual exploitability evidence through the existing strict review schema. The final business-risk score is not produced by a second free-form model call. Sentinel calculates it locally from persisted evidence:

```text
40% technical severity
20% exploitability
15% external exposure
15% asset importance
10% review confidence
```

The result is multiplied by a remediation factor:

- `1.00` — unresolved exposure;
- `0.70` — validated patch only;
- `0.35` — validated patch and passed regression proof;
- `0.15` — validated patch, passed proof, and explicit human approval.

The inherent score never changes when remediation progresses. The residual score shows the remaining release risk.

## Persisted fields

Each confirmed finding receives one `risk_intelligence` row containing:

- affected asset and component;
- asset type and attack surface;
- external exposure and required privilege;
- sensitive data or authority at risk;
- blast radius;
- five scoring factors;
- inherent and residual risk;
- priority and estimated effort;
- business-impact summary;
- ordered remediation plan;
- engine version and factor map.

Unconfirmed candidates do not receive a business-risk row.

## Executive report

```http
GET /scan/{scan_id}/executive-report
GET /scan/{scan_id}/executive-report?format=html
```

The report includes:

- overall posture from the highest residual risk;
- the ordinary fail-closed release gate;
- immediate and before-release actions;
- public exposures and affected assets;
- attack-surface and asset distribution;
- prioritized risks with factor breakdowns and remediation plans.

The executive score never overrides the release gate. A low aggregate score cannot make an incomplete, failed, or unapproved high-confidence finding pass.

## Finding-level API

```http
GET /scan/{scan_id}/risk-intelligence
GET /scan/{scan_id}/findings/{finding_id}/risk-intelligence
```

Risk intelligence is also included in the finding Evidence Bundle and covered by its section and payload SHA-256 hashes.

## Attack Graph v2

The attack path now contains nine stages:

```text
trust-boundary source
→ deterministic evidence
→ sensitive sink
→ affected asset
→ business impact
→ GPT-5.6 verdict
→ patch escrow
→ regression proof
→ human decision
```

The asset and impact nodes are derived from the same versioned risk engine used by the executive report.

## Limitations

- Asset importance is inferred from rule and repository-path evidence, not from a company CMDB.
- Effort ranges are prioritization hints, not delivery commitments.
- The model does not claim financial-loss estimates.
- Repository file renames and organization-specific data classifications require explicit external context in a future version.


## Project context in engine v2

Sentinel risk engine v2 accepts an immutable `ProjectContextSnapshot`. Explicit assets override the heuristic asset, exposure, data classification, privilege requirement, and business-impact inputs. Every persisted risk row records the profile version, context SHA-256, profile source, resolution source, and selected asset ID in `scoring_factors.context`. If no declared profile is assigned, the v1 heuristic remains the fallback.
