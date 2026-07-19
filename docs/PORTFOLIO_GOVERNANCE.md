# Portfolio Security Governance

Sentinel 1.9 adds a deterministic executive layer across independent root lineages. A portfolio does not merge scan history or pretend that unrelated repositories are one project. It keeps every lineage separate, selects one defensible head for each member, and rolls the resulting evidence into an auditable portfolio decision.

## Portfolio membership

A `SecurityPortfolio` contains explicit `PortfolioMember` rows. Each member stores:

- a root scan ID;
- a human-readable display name;
- an optional business unit;
- criticality (`low`, `medium`, `high`, or `critical`);
- an optional pinned scan ID.

Criticality weights are 1, 2, 3, and 4. They affect portfolio posture and residual-risk concentration, but never alter the underlying lineage evidence.

## Branch-head safety

A lineage can have multiple leaf scans after parallel rescans. Sentinel never silently chooses a sibling branch as the authoritative portfolio head.

- one leaf: the leaf is selected automatically;
- multiple leaves with no pin: evidence state is `ambiguous_head` and portfolio readiness fails closed;
- a pinned scan: Sentinel validates that it belongs to the selected root lineage and uses it explicitly.

This keeps portfolio reporting compatible with the direct-ancestor guarantees used by posture and remediation forecasting.

## Immutable governance profiles

Every portfolio has versioned `PortfolioGovernanceProfile` rows with canonical SHA-256. Updating governance creates a new version only when the normalized document changes.

The profile can constrain:

- maximum evidence age;
- missing, stale, unavailable, and ambiguous members;
- blocked member lineages;
- criticality-weighted posture score;
- weighted residual-risk concentration;
- overdue SLA debt;
- accepted-risk findings;
- missed objectives;
- off-track forecasts;
- whether every selected release gate, security policy, and exception-aware governance state must pass.

## Member snapshot

For each selected completed scan Sentinel builds the existing lineage posture and objective report, then records:

- release, policy, governance, and SLA state;
- posture score and residual risk;
- confirmed findings and policy blockers;
- accepted risk and overdue debt;
- objective state;
- forecast state, confidence, and projected active findings;
- evidence age and branch-head count.

No new model call is made. Repository code is not executed.

## Portfolio readiness

Member readiness is fail closed:

- `blocked` for missing, stale, failed, in-progress, or ambiguous evidence; blocked release/policy/governance; overdue SLA debt; missed objectives; or off-track/missed forecasts;
- `at_risk` for accepted-risk governance, SLA debt approaching deadline, at-risk objectives, or insufficient/at-risk forecasts;
- `passed` only when current evidence satisfies the strict member boundary.

Portfolio state is:

- `insufficient_evidence` when required evidence coverage is missing, stale, unavailable, ambiguous, or the portfolio is empty;
- `blocked` when a governance threshold is missed;
- `at_risk` when all governance checks pass but one or more members remain at risk;
- `passed` when all checks and members pass.

## Risk concentration

Residual risk is multiplied by member criticality. Sentinel reports each member's share of the weighted portfolio total. A portfolio can therefore expose concentration in one critical system instead of hiding it behind a simple average.

## API

```text
GET    /portfolios
POST   /portfolios
GET    /portfolios/{portfolio_id}
PUT    /portfolios/{portfolio_id}
POST   /portfolios/{portfolio_id}/members
DELETE /portfolios/{portfolio_id}/members/{root_scan_id}
GET    /portfolios/{portfolio_id}/governance
PUT    /portfolios/{portfolio_id}/governance
GET    /portfolios/{portfolio_id}/dashboard
GET    /portfolios/{portfolio_id}/evidence
```

The list and dashboard endpoints support HTML through `?format=html` or `Accept: text/html`.

## Portfolio evidence bundle

`sentinel-portfolio-evidence-v1` contains:

- application and engine versions;
- portfolio metadata and explicit membership;
- the exact governance profile version and hash;
- executive summary and every governance check;
- member snapshots and risk concentrations;
- SHA-256 for each top-level section;
- canonical payload SHA-256.

The bundle is a query-time snapshot. Its `generated_at`, selected heads, freshness calculation, governance profile, and integrity hashes define its reproducibility boundary.

## Limitations

Portfolio governance aggregates evidence already produced by Sentinel. It does not discover cross-repository data flows, infer organizational ownership, choose between ambiguous sibling branches, or treat an average score as permission to release. Those boundaries remain explicit in the report.
