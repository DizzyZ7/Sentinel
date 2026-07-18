# Security Policy Profiles

Sentinel 1.4 adds an immutable organizational policy layer above the ordinary fail-closed release gate.

The base gate remains authoritative and unchanged. A security policy profile can only add stricter release requirements based on project context; it cannot hide findings, approve patches, or bypass proof.

## Versioning

Each scan is assigned exactly one policy profile. Profiles are versioned per lineage root and identified by a canonical SHA-256 digest.

- updating a policy creates a new immutable version;
- the current scan retains its assigned version;
- the next rescan receives the latest version;
- policy compliance can be compared across scan generations.

## Policy document

```json
{
  "policy_name": "Production release policy",
  "base_block_on": "high",
  "fail_closed_on_unreviewed": true,
  "unreviewed_confidence_threshold": 0.9,
  "require_valid_patch_from": "high",
  "require_passed_proof_from": "high",
  "require_human_approval_from": "high",
  "production_block_on": "high",
  "public_asset_block_on": "medium",
  "restricted_data_block_on": "medium",
  "critical_asset_block_on": "medium",
  "frameworks": ["OWASP ASVS", "SOC 2"],
  "overrides": []
}
```

Requirement thresholds accept `low`, `medium`, `high`, `critical`, or `never`.

## Context-sensitive thresholds

The effective threshold is the strictest applicable value from:

- base policy;
- production environment;
- public exposure;
- restricted data classification;
- critical asset classification;
- matching policy overrides.

A high base policy may therefore treat a medium finding as release-blocking when it affects a public, restricted-data, or critical asset.

## Overrides

Overrides match one or more context dimensions. All populated dimensions must match; values within a dimension use OR semantics.

```json
{
  "override_id": "customer-data-release",
  "name": "Customer data requires verified approval",
  "asset_ids": ["customer-data-api"],
  "data_classifications": ["restricted"],
  "block_on": "medium",
  "require_valid_patch": true,
  "require_passed_proof": true,
  "require_human_approval": true
}
```

Supported match dimensions include asset IDs, repository-relative path patterns, exposure, data classification, criticality, environment, attack surface, and technical severity.

## API

```text
GET  /scan/{scan_id}/security-policy
PUT  /scan/{scan_id}/security-policy
POST /scan/{scan_id}/security-policy/preview
GET  /scan/{scan_id}/policy-compliance
GET  /scan/{current_scan_id}/policy-compliance/compare/{baseline_scan_id}
```

`preview` evaluates a candidate policy without saving it. The HTML policy editor is available with `?format=html`.

## Compliance semantics

For each in-scope finding, Sentinel records:

- effective threshold;
- matched overrides;
- required controls;
- satisfied controls;
- exact blocker reasons;
- project context used for the decision.

Control evidence is limited to persisted facts:

- validated patch;
- passed non-executing regression proof;
- explicit human approval.

No source code is executed and no repository dependency is installed.
