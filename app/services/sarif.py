from collections.abc import Iterable
from typing import Any

from app.models.finding import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def build_sarif(findings: Iterable[Finding]) -> dict[str, Any]:
    confirmed = [item for item in findings if item.confirmed and item.severity]
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in confirmed:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.recommendation or finding.static_rationale},
                "properties": {"tags": ["security", finding.language, finding.cwe or "unclassified"]},
            },
        )
        decision = finding.decision.decision if finding.decision else "pending"
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": LEVELS.get(finding.severity or "", "warning"),
                "message": {"text": finding.explanation or finding.static_rationale},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {"startLine": finding.line, "endLine": finding.end_line},
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "cvssLikeScore": finding.cvss_score,
                    "confidence": finding.confidence,
                    "cwe": finding.cwe,
                    "patchValid": finding.patch_valid,
                    "humanDecision": decision,
                    "regressionVerification": (
                        finding.verification.status if finding.verification else "not_available"
                    ),
                    "sourceExecutedDuringVerification": (
                        finding.verification.source_executed if finding.verification else False
                    ),
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "informationUri": "https://github.com/DizzyZ7/Sentinel",
                        "semanticVersion": "0.5.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
