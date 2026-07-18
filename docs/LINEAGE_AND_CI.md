# Scan lineage and CI regression gate

Sentinel 1.1 persists the relationship between repository scans instead of treating every comparison as an isolated pair. The lineage table is separate from the core `scans` table, so existing installations can create it through the normal idempotent metadata bootstrap without rewriting historical scan rows.

## Lineage model

Every newly created scan receives a lineage record:

```text
scan_id → parent_scan_id → root_scan_id → generation
```

- an uploaded, cloned, or built-in demo scan starts at generation `0` and points to itself as the root;
- a rescan points to the selected baseline as its parent;
- a rescan of a rescan keeps the same root and increments generation;
- old scans created before 1.1 are registered lazily when they become a rescan baseline.

Read the complete history:

```bash
curl http://localhost:8000/scan/<scan_id>/lineage
```

The response includes every persisted node, the immediate parent, the root, and which earlier completed nodes are eligible baselines. The judge and comparison views use this endpoint to populate their baseline selectors.

## CI gate endpoint

For a rescan, the immediate parent is selected automatically:

```bash
curl --fail-with-body \
  http://localhost:8000/scan/<current_scan_id>/ci-gate
```

Choose another earlier scan from the same lineage:

```bash
curl --fail-with-body \
  'http://localhost:8000/scan/<current_scan_id>/ci-gate?baseline_scan_id=<baseline_scan_id>&block_on=high'
```

Successful evaluations return HTTP `200`, `X-Sentinel-Exit-Code: 0`, and `exit_code: 0` in JSON. A blocking introduced or changed finding returns HTTP `409`, `X-Sentinel-Exit-Code: 1`, and `exit_code: 1`. Invalid lineage, unfinished scans, missing baselines, and transport errors are operational failures rather than security-regression results.

## Stable CLI exit codes

Use the packaged client when a workflow needs stable process codes rather than curl's HTTP error code:

```bash
sentinel-check-delta \
  --base-url http://localhost:8000 \
  --current-scan-id <current_scan_id>
```

Optional explicit baseline:

```bash
sentinel-check-delta \
  --current-scan-id <current_scan_id> \
  --baseline-scan-id <baseline_scan_id> \
  --block-on high
```

Exit codes:

```text
0 → no blocking introduced or changed security regression
1 → the no-new-risk delta gate is blocked
2 → network, configuration, API, or lineage error
```

`--allow-unreviewed` disables fail-closed handling for incomplete deep review. It should only be used when the calling CI policy explicitly accepts deterministic candidates without a contextual verdict.

## GitHub Actions example

```yaml
- name: Check Sentinel security delta
  run: >-
    sentinel-check-delta
    --base-url "$SENTINEL_URL"
    --current-scan-id "$SENTINEL_SCAN_ID"
```

The command prints the full machine-readable gate response before exiting. Persistent legacy findings remain visible in the full gate and comparison report but do not fail this incremental CI check.

## Safety boundaries

- baseline selection is restricted to earlier completed scans in the same persisted lineage;
- lineage creation does not execute source or install repository dependencies;
- the CI endpoint derives its result only from already persisted comparison evidence;
- exit code `1` is reserved for a real policy block, while operational uncertainty fails separately with code `2`;
- rescan continues to create a new isolated workspace and uses the ordinary ingestion, review, patch, proof, and human-decision pipeline.
