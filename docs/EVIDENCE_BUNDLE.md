# Sentinel Evidence Bundle

The evidence bundle is the portable trust artifact for one finding.

## Contents

- scan provenance and repository-structure digest;
- deterministic rule evidence and a secret-sanitized snippet;
- GPT verdict and privacy-safe model-call audit;
- patch validation state, raw patch SHA-256, size, changed-line count, and sanitized diff;
- non-executing regression proof;
- explicit human decision;
- fail-closed release policy result;
- nine-stage Attack Graph v2 with affected asset and business impact;
- deterministic risk intelligence and scoring factors;
- versions of every security-sensitive boundary, including the risk engine.

## Integrity model

Sentinel serializes each evidence section as sorted-key UTF-8 JSON with compact separators and computes SHA-256. It then computes a second SHA-256 over the complete section map.

```text
section data -> canonical JSON -> section SHA-256
all sections -> canonical JSON -> payload SHA-256
```

The digest proves that a downloaded bundle has not been modified after generation. It is not a cryptographic identity signature and does not attest that a third party trusts the result.

## Privacy model

Original credential-like values are not exported in source snippets or unified diffs. Sentinel replaces them with typed placeholders while preserving line structure. Raw patch bytes remain local and are represented in the bundle by their SHA-256 and size.

## Endpoint

```http
GET /scan/{scan_id}/findings/{finding_id}/evidence-bundle
```

The response is downloadable JSON and includes the canonical payload digest in the `X-Sentinel-Evidence-SHA256` header.


Project-context provenance is included inside the risk-intelligence section: assigned profile version, context SHA-256, profile source, resolution source, project name, and matched asset ID. The full mutable profile catalog is not duplicated; its canonical hash provides the audit link to the immutable profile record.
