# Project Context Profiles

Sentinel 1.3 lets a team declare the business context that deterministic risk scoring cannot infer reliably from file names alone.

## Why profiles exist

A SQL injection in a disposable development tool and the same SQL injection in a public production payments service should not receive identical asset and exposure factors. Project Context Profiles provide this missing information while preserving Sentinel's evidence-first trust model.

Profiles never change static findings, GPT-5.6 verdicts, patch validation, regression proof, human decisions, or the ordinary fail-closed release gate. They only refine the asset, exposure, data classification, business impact, and priority inputs used by Risk Intelligence.

## Immutable versioning

Every lineage root owns an ordered profile history:

```text
profile v1 ── assigned to scan generation 0
profile v2 ── created after review
profile v2 ── assigned to the next rescan
profile v3 ── assigned to a later rescan
```

Changing a profile creates a new immutable version. Existing scans retain their original assignment and context SHA-256. Historical executive reports and Evidence Bundles therefore remain reproducible.

## Profile document

```json
{
  "project_name": "Payments API",
  "environment": "production",
  "internet_exposed": true,
  "default_criticality": "high",
  "default_exposure": "public",
  "default_data_classification": "confidential",
  "compliance_frameworks": ["PCI DSS", "SOC 2"],
  "assets": [
    {
      "asset_id": "payment-service",
      "name": "Payment processing service",
      "asset_type": "financial_service",
      "path_patterns": ["payments/**", "app/routes/payments.py"],
      "criticality": "critical",
      "exposure": "public",
      "data_classification": "restricted",
      "data_types": ["payment records", "customer identifiers"],
      "privilege_required": "none",
      "business_impact": "Compromise can expose or alter payment records.",
      "owner": "Payments platform"
    }
  ]
}
```

Path patterns are repository-relative glob expressions. Absolute paths and `..` components are rejected. When several assets match, Sentinel deterministically selects the most specific pattern and then the lexicographically smallest asset ID.

## Scoring behavior

An explicitly matched asset provides:

- asset name and type;
- criticality-derived asset importance;
- exposure and exposure score;
- data classification and data types;
- privilege requirement;
- business-impact description.

Asset importance is deterministic:

```text
criticality base
+ environment modifier
+ data-classification modifier
capped at 1.0
```

Production adds `0.05`, staging adds `0.02`, confidential data adds `0.04`, and restricted data adds `0.08`. Exposure uses fixed values documented in the source service. The complete factors, selected asset ID, profile version, source, and context SHA-256 are persisted inside the risk record.

An inferred profile with no declared assets preserves the Sentinel 1.2 path heuristic. A declared profile with no matching asset applies the profile defaults while retaining the heuristic asset label.

## API

Read the profile assigned to a scan and its version history:

```http
GET /scan/{scan_id}/project-context
GET /scan/{scan_id}/project-context?format=html
```

Create a new immutable version for future rescans:

```http
PUT /scan/{scan_id}/project-context
Content-Type: application/json
```

Preview a document against an already completed scan without persisting or changing evidence:

```http
POST /scan/{scan_id}/project-context/preview
Content-Type: application/json
```

The preview returns a full executive report and context hash. The next rescan automatically uses the latest profile version in the lineage.

A profile can also be supplied during the initial ZIP or Git scan as the multipart form field `project_context`, containing the JSON document.

## Safety and limitations

- Profile documents are data only and are never executed.
- Asset glob patterns are matched against normalized repository-relative paths.
- Updating a profile never mutates historical assignments or persisted risk evidence.
- Preview reports are clearly marked as preview and are not written to the Evidence Bundle.
- Business context can improve prioritization but cannot make the ordinary release gate pass.
- Incorrect declarations can distort priority; the profile hash and exact scoring factors remain visible for audit.
