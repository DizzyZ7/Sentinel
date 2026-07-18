import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.core.version import STATIC_RULESET_VERSION
from app.services.static_analysis import analyze_repository


@dataclass(frozen=True, slots=True)
class CaseResult:
    id: str
    filename: str
    language: str
    expected_rules: list[str]
    observed_rules: list[str]
    true_positives: list[str]
    false_positives: list[str]
    false_negatives: list[str]
    passed: bool


def _ratio(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else round(numerator / denominator, 4)


def evaluate_manifest(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases_root = manifest_path.parent / "cases"
    case_results: list[CaseResult] = []
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    total_tp = 0
    total_fp = 0
    total_fn = 0

    for case in manifest["cases"]:
        source = cases_root / case["filename"]
        expected = set(case["expected_rules"])
        findings = analyze_repository(
            cases_root,
            [{"path": case["filename"], "language": case["language"], "size": source.stat().st_size}],
        )
        observed = {finding.rule_id for finding in findings}
        true_positives = sorted(expected & observed)
        false_positives = sorted(observed - expected)
        false_negatives = sorted(expected - observed)

        for rule in true_positives:
            per_rule[rule]["tp"] += 1
        for rule in false_positives:
            per_rule[rule]["fp"] += 1
        for rule in false_negatives:
            per_rule[rule]["fn"] += 1

        total_tp += len(true_positives)
        total_fp += len(false_positives)
        total_fn += len(false_negatives)
        case_results.append(
            CaseResult(
                id=case["id"],
                filename=case["filename"],
                language=case["language"],
                expected_rules=sorted(expected),
                observed_rules=sorted(observed),
                true_positives=true_positives,
                false_positives=false_positives,
                false_negatives=false_negatives,
                passed=not false_positives and not false_negatives,
            )
        )

    passed_cases = sum(result.passed for result in case_results)
    positive_cases = sum(bool(result.expected_rules) for result in case_results)
    negative_cases = len(case_results) - positive_cases
    metrics = {
        "case_count": len(case_results),
        "positive_case_count": positive_cases,
        "negative_case_count": negative_cases,
        "passed_cases": passed_cases,
        "failed_cases": len(case_results) - passed_cases,
        "case_pass_rate": _ratio(passed_cases, len(case_results)),
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
        "precision": _ratio(total_tp, total_tp + total_fp),
        "recall": _ratio(total_tp, total_tp + total_fn),
    }

    return {
        "schema_version": "sentinel-static-eval-v1",
        "ruleset_version": STATIC_RULESET_VERSION,
        "scope": (
            "Curated deterministic rule-regression corpus. These metrics validate the included fixtures and "
            "must not be interpreted as general-world vulnerability detection accuracy."
        ),
        "metrics": metrics,
        "per_rule": dict(sorted(per_rule.items())),
        "cases": [asdict(result) for result in case_results],
    }


def to_markdown(result: dict[str, Any]) -> str:
    metrics = result["metrics"]
    lines = [
        "# Sentinel deterministic evaluation",
        "",
        f"Ruleset: `{result['ruleset_version']}`",
        "",
        result["scope"],
        "",
        "| Metric | Result |",
        "| --- | ---: |",
        f"| Cases | {metrics['case_count']} |",
        f"| Exact case pass rate | {metrics['passed_cases']}/{metrics['case_count']} "
        f"({metrics['case_pass_rate']:.0%}) |",
        f"| True positives | {metrics['true_positives']} |",
        f"| False positives | {metrics['false_positives']} |",
        f"| False negatives | {metrics['false_negatives']} |",
        f"| Micro precision | {metrics['precision']:.0%} |",
        f"| Micro recall | {metrics['recall']:.0%} |",
        "",
        "## Cases",
        "",
        "| Case | Expected | Observed | Status |",
        "| --- | --- | --- | --- |",
    ]
    for case in result["cases"]:
        expected = ", ".join(case["expected_rules"]) or "none"
        observed = ", ".join(case["observed_rules"]) or "none"
        status = "PASS" if case["passed"] else "FAIL"
        lines.append(f"| `{case['id']}` | `{expected}` | `{observed}` | {status} |")
    return "\n".join(lines) + "\n"
