from __future__ import annotations

from typing import Any

from app.core.version import APP_VERSION

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def build_local_sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in report["findings"]:
        rule_id = finding["rule_id"]
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding["title"],
                "shortDescription": {"text": finding["title"]},
                "help": {"text": finding["static_rationale"]},
                "properties": {
                    "tags": ["security", "static-analysis", finding["language"]],
                    "precision": "medium",
                },
            },
        )
        confidence = float(finding["static_confidence"])
        results.append(
            {
                "ruleId": rule_id,
                "kind": "review",
                "level": "warning" if confidence >= 0.9 else "note",
                "baselineState": "unchanged" if finding["baseline_state"] == "existing" else "new",
                "message": {"text": finding["static_rationale"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding["file_path"]},
                            "region": {
                                "startLine": finding["line"],
                                "endLine": finding["end_line"],
                            },
                        }
                    }
                ],
                "partialFingerprints": {"sentinel/local/v1": finding["fingerprint"]},
                "properties": {
                    "classification": "deterministic_candidate",
                    "confirmed": False,
                    "staticConfidence": confidence,
                    "sourceSha256": finding["source_sha256"],
                    "redactionCount": finding["redaction_count"],
                    "sourceExecuted": False,
                    "dependenciesInstalled": False,
                    "patchApplied": False,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "automationDetails": {"id": "sentinel/local-static-candidates"},
                "tool": {
                    "driver": {
                        "name": "Sentinel Local CLI",
                        "informationUri": "https://github.com/DizzyZ7/Sentinel",
                        "semanticVersion": APP_VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": report["safety"],
                    }
                ],
                "properties": {
                    "schemaVersion": report["schema_version"],
                    "reportSha256": report["report_sha256"],
                    "changedOnly": report["mode"]["changed_only"],
                    "baseRef": report["mode"]["base_ref"],
                },
                "results": results,
            }
        ],
    }
