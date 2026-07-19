# Local CLI and changed-files gate

Sentinel 2.2 adds a local developer path that runs the deterministic candidate layer directly against a repository directory. It does not start FastAPI or PostgreSQL, call GPT-5.6, execute repository source, install repository dependencies, apply patches, or claim that a static candidate is a confirmed vulnerability.

## Install

From a checked-out Sentinel source tree:

```bash
python -m pip install .
```

The package exposes one top-level command:

```bash
sentinel --version
sentinel scan --help
```

## Full local scan

```bash
sentinel scan .
```

The console report identifies every result as a deterministic candidate. It includes the analyzed file count, new/existing fingerprint state, fail policy, safety boundary, and canonical report SHA-256.

Write machine-readable evidence and SARIF in one pass:

```bash
sentinel scan . \
  --format text \
  --json-output sentinel-local-scan.json \
  --sarif-output sentinel-local-scan.sarif
```

Static evidence snippets are secret-sanitized before they enter JSON. `--omit-snippets` removes even sanitized snippets while retaining rule, path, line, confidence, source hash, fingerprint, and redaction count.

## Changed-files scan

For working-tree and untracked changes:

```bash
sentinel scan . --changed-only
```

For committed pull-request changes against a locally available base:

```bash
git fetch --no-tags origin main
sentinel scan . \
  --changed-only \
  --base-ref origin/main
```

Changed-file selection uses Git plumbing only. Sentinel disables repository-configured fsmonitor, external diff, and textconv execution for its Git reads. It includes added, copied, modified, renamed, working-tree, and non-ignored untracked files. Deleted files are not scanned. A non-Git directory cannot use `--changed-only`.

A full Git scan uses `git ls-files -co --exclude-standard`, so tracked files and non-ignored untracked files are included while nested `.gitignore` rules are respected. A non-Git directory uses the root `.gitignore` through Git wildmatch semantics and always excludes Sentinel's built-in generated/vendor directories.

## Baseline and no-new-risk policy

Create a baseline without blocking:

```bash
sentinel scan . \
  --format json \
  --output sentinel-baseline.json \
  --fail-on never
```

Compare a later full scan:

```bash
sentinel scan . \
  --baseline sentinel-baseline.json \
  --fail-on new \
  --fail-confidence 0.80 \
  --json-output sentinel-current.json
```

Fingerprints use rule ID, normalized repository-relative path, language, and whitespace-normalized evidence rather than line number. Moving the same evidence within a file therefore remains `existing`. A changed-only comparison is intentionally marked `partial`; it does not claim that absent baseline findings were resolved.

Policy modes:

```text
never → report only
any   → block on every candidate at or above --fail-confidence
new   → block only on new candidate fingerprints at or above the threshold
```

Stable exit codes:

```text
0 → scan completed and policy passed
1 → scan completed and policy blocked
2 → CLI, baseline, Git, or configuration error
3 → local scan or output failure
```

These codes are separate from the server-backed `sentinel-check-delta` client. The local CLI evaluates deterministic candidates only; the server gate can additionally evaluate GPT-5.6 review, patch proof, human decision, policy, exceptions, and lineage.

## SARIF semantics

Local SARIF results are deliberately emitted as:

```text
kind = review
confirmed = false
classification = deterministic_candidate
sourceExecuted = false
```

Confidence controls `note` versus `warning`; it is not presented as CVSS severity. Every result includes a Sentinel fingerprint, source SHA-256, baseline state, and non-execution properties. Uploading SARIF does not make the findings confirmed.

## GitHub Action

A composite action is committed at `action.yml`. The action installs only the local CLI package plus `pathspec`; importing the command does not load FastAPI, Uvicorn, or SQLAlchemy:

```yaml
- name: Scan changed source files
  uses: DizzyZ7/Sentinel@main
  with:
    changed-only: "true"
    fail-on: new
    fail-confidence: "0.80"
```

On pull requests, the action derives and fetches `origin/$GITHUB_BASE_REF` when `base-ref` is omitted. It writes:

```text
sentinel-local-scan.json
sentinel-local-scan.sarif
```

A complete workflow with SARIF upload and retained evidence is available in [`examples/sentinel-local-scan.yml`](../examples/sentinel-local-scan.yml).

## Discovery and safety limits

- supported files: Python, JavaScript, JSX, MJS, CJS, TypeScript, and TSX;
- default maximum source file size: 1,000,000 bytes;
- default maximum supported file count: 5,000;
- symlinks are never followed;
- binary or non-UTF-8 files are skipped;
- built-in ignored directories include `.git`, virtual environments, `node_modules`, build output, coverage output, caches, and `.next`;
- source file SHA-256 values cover exactly the bytes analyzed;
- reports contain no absolute repository path;
- deterministic scanning does not execute source or install its dependencies.

## Evidence report integrity

The JSON schema is `sentinel-local-scan-v1`. `report_sha256` is calculated from canonical UTF-8 JSON before the digest field is added. The report also includes:

- application and ruleset versions;
- scan mode and Git scope;
- selected files, byte counts, language, and source SHA-256;
- skip counters;
- sanitized candidates and stable fingerprints;
- baseline comparison scope;
- policy blockers and process exit code;
- explicit safety booleans.

The helper `verify_report_sha256()` independently recalculates the digest.
