# Baseline comparison and delta policy

Sentinel 1.0 compares two completed repository snapshots without re-executing either repository. The comparison is computed from persisted deterministic candidates, deep-review verdicts, patch state, regression proof, and human decisions.

## Create the next scan

For a Git baseline or a preserved ZIP archive:

```bash
curl -X POST http://localhost:8000/scan/<baseline_scan_id>/rescan
```

The response includes the new scan ID and a ready-to-use `comparison_url`. The judge view also exposes this workflow through **Start rescan** and automatically opens the comparison after completion.

A separately uploaded or cloned scan can be compared as well:

```bash
curl -F "archive=@repository-v2.zip" http://localhost:8000/scan/repo
curl 'http://localhost:8000/scan/<current_scan_id>/compare/<baseline_scan_id>'
```

HTML view:

```bash
open 'http://localhost:8000/scan/<current_scan_id>/compare/<baseline_scan_id>?format=html'
```

## Matching model

Sentinel does not use line numbers as identity. Each finding receives a SHA-256 fingerprint from:

```text
rule ID + normalized path + language + normalized evidence snippet
```

This produces four states:

- **persistent** — the exact fingerprint exists in both scans, even if the line moved;
- **changed** — the same rule remains in the same file, but its evidence fingerprint changed;
- **introduced** — evidence exists only in the current scan;
- **resolved** — baseline evidence no longer exists in the current scan.

After exact matching, remaining findings with the same rule and path are paired deterministically by nearest line position. File renames are intentionally represented as resolved plus introduced because Sentinel does not guess rename intent from security evidence alone.

## Full gate versus delta gate

The ordinary release gate evaluates all current high/critical exposure. The delta gate evaluates only introduced and changed evidence.

This supports incremental adoption:

```text
legacy high finding persists     → full gate blocked, delta gate passed
new unresolved high finding      → full gate blocked, delta gate blocked
new high finding fully remediated
(valid patch + passed proof + approval) → delta gate passed
```

High-confidence evidence whose deep review failed, was skipped, or remains pending also fails the delta gate when `fail_closed_on_unreviewed=true`.

The delta gate does not hide legacy debt. Persistent findings remain visible in the comparison and the ordinary full gate.

## Safety properties

- scanned source is never executed for comparison;
- no new model call is made merely to compare completed scans;
- snippets are not returned by the comparison API, only privacy-safe fingerprints and finding metadata;
- the preserved ZIP archive may only be copied from inside Sentinel's configured scan root;
- rescan uses the normal ingestion, review, validation, proof, and policy pipeline.
