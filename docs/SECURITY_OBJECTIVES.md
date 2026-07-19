# Security Objectives and Remediation Forecasting

Sentinel 1.8 adds a deterministic planning layer above the immutable evidence, policy, exception, SLA, and posture history. It answers two separate questions:

1. Has the selected scan reached the security state declared by the organization?
2. Given the observed ancestor-chain inflow and resolution rate, is the current backlog likely to reach the declared target by its deadline?

The objective layer never changes findings, human decisions, release gates, policy compliance, accepted-risk records, SLA clocks, or historical posture points.

## Immutable profiles

Each lineage stores versioned `SecurityObjectiveProfile` rows. `ScanObjectiveAssignment` binds every scan to one exact objective version.

- the first scan receives a declared profile or a deterministic 90-day inferred profile;
- saving a document creates a new immutable version only when its canonical SHA-256 changes;
- the current scan retains its assigned version;
- the latest version is assigned to the next rescan;
- preview evaluates an in-memory document and writes no profile or evidence;
- historical reports always use the exact profile assigned to that scan.

The objective document contains:

- target date;
- maximum posture score;
- maximum confirmed findings;
- maximum policy blockers;
- maximum overdue SLA findings;
- maximum accepted-risk findings;
- minimum SLA attainment rate;
- maximum mean remediation time;
- maximum exact-fingerprint recurrence rate;
- optional requirements for the raw release gate, security policy, and exception-aware governance to pass;
- whether missing remediation history is itself blocking;
- minimum acceptable forecast confidence.

## Objective evaluation

`sentinel-security-objective-v1` reads the current point from the lineage posture report and produces explicit checks with:

- metric key and human-readable label;
- source section;
- operator and target;
- actual value;
- `met`, `missed`, or `not_measurable` status;
- deterministic explanation.

The report state is:

- `met` when every measurable requirement passes and missing history is allowed;
- `at_risk` when one or more checks miss before the target date;
- `missed` when one or more checks miss after the target date;
- `insufficient_history` when history is required but a remediation metric cannot yet be measured.

A missing metric never receives a fabricated value.

## Remediation forecast

`sentinel-remediation-forecast-v1` uses only the selected scan's direct ancestor chain. Sibling branches are excluded.

For each measurable interval it records:

- elapsed days;
- introduced findings;
- reopened exact fingerprints;
- resolved findings;
- observed inflow per day;
- observed resolution capacity per day.

Changed evidence remains one continuous remediation episode and is not counted as a resolution or a new introduction.

Aggregate rates are calculated as:

```text
inflow rate     = (introduced + reopened) / observed days
resolution rate = resolved / observed days
net burn rate   = resolution rate - inflow rate
```

The projected active backlog at the objective date is:

```text
current active + inflow rate × horizon - resolution rate × horizon
```

The projection is floored at zero. Sentinel also reports the resolution rate required to reach the declared maximum active backlog.

## Confidence

Forecast confidence is deliberately explicit:

- `insufficient_history`: no positive-duration ancestor interval or less than one observed day;
- `low`: measurable history exists but does not meet medium thresholds;
- `medium`: at least three intervals, 30 days, and two resolution events;
- `high`: at least five intervals, 90 days, and five resolution events.

A projection that numerically reaches the target but does not meet the profile's minimum confidence is reported as `at_risk`, not `on_track`.

## Forecast states

- `met`: the objective is already met at the scan's completion time;
- `on_track`: projected backlog reaches the target with acceptable confidence;
- `at_risk`: projection is near the target or confidence is below the declared minimum;
- `off_track`: projected backlog materially exceeds the target;
- `missed`: the target date has passed while the objective remains unmet;
- `insufficient_history`: Sentinel cannot produce a defensible projection.

## Reproducibility boundary

Objective evaluation and forecasting use the selected scan's completion time as `as_of`. This keeps historical reports reproducible. A fresh forecast requires a new rescan rather than silently changing an old report as wall-clock time passes.

The forecast is deterministic. It makes no GPT call, executes no repository code, installs no repository dependency, and never applies a patch.

## API

```text
GET  /scan/{scan_id}/security-objectives
PUT  /scan/{scan_id}/security-objectives
POST /scan/{scan_id}/security-objectives/preview
GET  /scan/{scan_id}/objective-report
```

Both status and report endpoints support HTML through `?format=html` or the `Accept: text/html` header.

Initial Git or ZIP ingestion accepts an optional multipart `security_objectives` JSON document. Rescans inherit the latest objective version in the same lineage.

## Evidence Bundle

The finding Evidence Bundle includes:

- the assigned objective profile ID, version, and SHA-256;
- every objective check;
- evaluation state and deadline state;
- forecast confidence and status;
- interval samples and rates;
- assumptions and confidence reasons;
- objective and forecast engine versions.

The objective section receives its own SHA-256 and participates in the canonical payload hash.

## Limitations

The forecast is a transparent capacity projection, not a promise. It assumes observed lineage rates continue and does not infer staffing changes, release freezes, future architecture changes, file renames, semantic equivalence, or unobserved vulnerabilities. Sentinel exposes these assumptions directly instead of hiding them behind an opaque score.
