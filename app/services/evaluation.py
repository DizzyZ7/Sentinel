from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from app.core.version import APP_VERSION, STATIC_RULESET_VERSION
from app.services.patches import validate_and_store_patch
from app.services.regression import verify_patch_regression
from app.services.static_analysis import analyze_repository


@dataclass(frozen=True, slots=True)
class CaseResult:
    id: str
    filename: str
    language: str
    classification: str
    pattern: str
    difficulty: str
    tags: list[str]
    target_rules: list[str]
    expected_rules: list[str]
    observed_rules: list[str]
    true_positives: list[str]
    false_positives: list[str]
    false_negatives: list[str]
    targeted_true_negatives: list[str]
    source_sha256: str
    passed: bool


@dataclass(frozen=True, slots=True)
class RemediationCaseResult:
    id: str
    rule_id: str
    language: str
    difficulty: str
    expected_patch_valid: bool
    observed_patch_valid: bool
    expected_verification: str | None
    observed_verification: str | None
    expected_error_contains: str | None
    observed_error: str | None
    source_sha256: str
    patch_sha256: str
    source_executed: bool
    passed: bool


def _ratio(numerator: int, denominator: int) -> float:
    return 1.0 if denominator == 0 else round(numerator / denominator, 4)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _group_metrics() -> dict[str, int]:
    return {
        "cases": 0,
        "passed_cases": 0,
        "positive_cases": 0,
        "negative_cases": 0,
        "multi_signal_cases": 0,
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
    }


def _finalize_group(item: dict[str, Any]) -> dict[str, Any]:
    item = dict(item)
    item["failed_cases"] = item["cases"] - item["passed_cases"]
    item["case_pass_rate"] = _ratio(item["passed_cases"], item["cases"])
    item["precision"] = _ratio(item["tp"], item["tp"] + item["fp"])
    item["recall"] = _ratio(item["tp"], item["tp"] + item["fn"])
    item["specificity"] = _ratio(item["tn"], item["tn"] + item["fp"])
    return item


def _validate_static_manifest(manifest: dict[str, Any], cases_root: Path) -> dict[str, dict[str, str]]:
    if manifest.get("schema_version") != 2:
        raise ValueError("Static evaluation manifest schema_version must be 2")
    rules = manifest.get("rules")
    cases = manifest.get("cases")
    if not isinstance(rules, list) or not rules:
        raise ValueError("Static evaluation manifest must declare a non-empty rule inventory")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Static evaluation manifest must declare cases")

    rule_inventory: dict[str, dict[str, str]] = {}
    for rule in rules:
        rule_id = rule.get("id")
        if not rule_id or rule_id in rule_inventory:
            raise ValueError("Static rule inventory contains a missing or duplicate id")
        rule_inventory[rule_id] = {
            "family": str(rule.get("family") or "unknown"),
            "language": str(rule.get("language") or "unknown"),
        }

    ids: set[str] = set()
    filenames: set[str] = set()
    for case in cases:
        case_id = case.get("id")
        filename = case.get("filename")
        if not case_id or case_id in ids:
            raise ValueError("Static evaluation cases contain a missing or duplicate id")
        if not filename or filename in filenames:
            raise ValueError("Static evaluation cases contain a missing or duplicate filename")
        ids.add(case_id)
        filenames.add(filename)
        source = cases_root / filename
        if not source.is_file():
            raise ValueError(f"Static evaluation source is missing: {filename}")

        expected = set(case.get("expected_rules") or [])
        target = set(case.get("target_rules") or [])
        unknown = (expected | target) - set(rule_inventory)
        if unknown:
            raise ValueError(f"Case {case_id} references unknown rules: {sorted(unknown)}")
        if not expected.issubset(target):
            raise ValueError(f"Case {case_id} expected_rules must be a subset of target_rules")
        if not target:
            raise ValueError(f"Case {case_id} must target at least one rule")
        classification = case.get("classification")
        expected_classification = "multi_signal" if len(expected) > 1 else ("positive" if expected else "negative")
        if classification != expected_classification:
            raise ValueError(
                f"Case {case_id} classification={classification!r}; expected {expected_classification!r}"
            )
        if case.get("difficulty") not in {"basic", "edge", "adversarial"}:
            raise ValueError(f"Case {case_id} has an unsupported difficulty")
        if not case.get("pattern"):
            raise ValueError(f"Case {case_id} must declare a pattern")
    return rule_inventory


def evaluate_manifest(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases_root = manifest_path.parent / "cases"
    rule_inventory = _validate_static_manifest(manifest, cases_root)
    case_results: list[CaseResult] = []

    per_rule: dict[str, dict[str, Any]] = {}
    for rule_id, metadata in rule_inventory.items():
        per_rule[rule_id] = {
            "family": metadata["family"],
            "language": metadata["language"],
            "positive_cases": 0,
            "negative_cases": 0,
            "edge_cases": 0,
            "multi_signal_cases": 0,
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "tn": 0,
        }

    per_language: dict[str, dict[str, int]] = defaultdict(_group_metrics)
    per_difficulty: dict[str, dict[str, int]] = defaultdict(_group_metrics)
    per_classification: dict[str, dict[str, int]] = defaultdict(_group_metrics)

    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_tn = 0

    corpus_material: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        source = cases_root / case["filename"]
        expected = set(case["expected_rules"])
        target = set(case["target_rules"])
        findings = analyze_repository(
            cases_root,
            [{"path": case["filename"], "language": case["language"], "size": source.stat().st_size}],
        )
        observed = {finding.rule_id for finding in findings}
        true_positives = sorted(expected & observed)
        false_positives = sorted(observed - expected)
        false_negatives = sorted(expected - observed)
        targeted_true_negatives = sorted((target - expected) - observed)
        passed = not false_positives and not false_negatives

        source_sha256 = _sha256_file(source)
        corpus_material.append(
            {
                "case": case,
                "source_sha256": source_sha256,
            }
        )

        for rule_id in target:
            item = per_rule[rule_id]
            is_expected = rule_id in expected
            is_observed = rule_id in observed
            if is_expected:
                item["positive_cases"] += 1
            else:
                item["negative_cases"] += 1
            if case["difficulty"] != "basic":
                item["edge_cases"] += 1
            if case["classification"] == "multi_signal":
                item["multi_signal_cases"] += 1
            if is_expected and is_observed:
                item["tp"] += 1
            elif is_expected and not is_observed:
                item["fn"] += 1
            elif not is_expected and is_observed:
                item["fp"] += 1
            else:
                item["tn"] += 1

        for rule_id in observed - expected:
            if rule_id not in target and rule_id in per_rule:
                per_rule[rule_id]["fp"] += 1

        total_tp += len(true_positives)
        total_fp += len(false_positives)
        total_fn += len(false_negatives)
        total_tn += len(targeted_true_negatives)

        for group_name, group_key in (
            ("language", case["language"]),
            ("difficulty", case["difficulty"]),
            ("classification", case["classification"]),
        ):
            target_map = {
                "language": per_language,
                "difficulty": per_difficulty,
                "classification": per_classification,
            }[group_name]
            group = target_map[group_key]
            group["cases"] += 1
            group["passed_cases"] += int(passed)
            group["positive_cases"] += int(bool(expected))
            group["negative_cases"] += int(not expected)
            group["multi_signal_cases"] += int(case["classification"] == "multi_signal")
            group["tp"] += len(true_positives)
            group["fp"] += len(false_positives)
            group["fn"] += len(false_negatives)
            group["tn"] += len(targeted_true_negatives)

        case_results.append(
            CaseResult(
                id=case["id"],
                filename=case["filename"],
                language=case["language"],
                classification=case["classification"],
                pattern=case["pattern"],
                difficulty=case["difficulty"],
                tags=sorted(case.get("tags") or []),
                target_rules=sorted(target),
                expected_rules=sorted(expected),
                observed_rules=sorted(observed),
                true_positives=true_positives,
                false_positives=false_positives,
                false_negatives=false_negatives,
                targeted_true_negatives=targeted_true_negatives,
                source_sha256=source_sha256,
                passed=passed,
            )
        )

    passed_cases = sum(result.passed for result in case_results)
    positive_cases = sum(bool(result.expected_rules) for result in case_results)
    negative_cases = len(case_results) - positive_cases
    multi_signal_cases = sum(result.classification == "multi_signal" for result in case_results)
    edge_cases = sum(result.difficulty != "basic" for result in case_results)
    metrics = {
        "case_count": len(case_results),
        "positive_case_count": positive_cases,
        "negative_case_count": negative_cases,
        "multi_signal_case_count": multi_signal_cases,
        "edge_case_count": edge_cases,
        "passed_cases": passed_cases,
        "failed_cases": len(case_results) - passed_cases,
        "case_pass_rate": _ratio(passed_cases, len(case_results)),
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
        "targeted_true_negatives": total_tn,
        "precision": _ratio(total_tp, total_tp + total_fp),
        "recall": _ratio(total_tp, total_tp + total_fn),
        "specificity": _ratio(total_tn, total_tn + total_fp),
    }

    finalized_rules: dict[str, dict[str, Any]] = {}
    for rule_id, item in sorted(per_rule.items()):
        finalized = dict(item)
        finalized["precision"] = _ratio(item["tp"], item["tp"] + item["fp"])
        finalized["recall"] = _ratio(item["tp"], item["tp"] + item["fn"])
        finalized["specificity"] = _ratio(item["tn"], item["tn"] + item["fp"])
        finalized_rules[rule_id] = finalized

    missing_positive = sorted(rule_id for rule_id, item in per_rule.items() if item["positive_cases"] == 0)
    missing_negative = sorted(rule_id for rule_id, item in per_rule.items() if item["negative_cases"] == 0)
    missing_edge = sorted(rule_id for rule_id, item in per_rule.items() if item["edge_cases"] == 0)
    coverage = {
        "known_rule_count": len(rule_inventory),
        "rules_with_positive_support": len(rule_inventory) - len(missing_positive),
        "rules_with_negative_support": len(rule_inventory) - len(missing_negative),
        "rules_with_edge_support": len(rule_inventory) - len(missing_edge),
        "missing_positive_support": missing_positive,
        "missing_negative_support": missing_negative,
        "missing_edge_support": missing_edge,
        "positive_and_negative_complete": not missing_positive and not missing_negative,
        "edge_complete": not missing_edge,
    }

    return {
        "schema_version": "sentinel-static-eval-v2",
        "corpus_version": manifest["corpus_version"],
        "corpus_sha256": _sha256_bytes(_canonical_bytes(corpus_material)),
        "ruleset_version": STATIC_RULESET_VERSION,
        "scope": (
            "Committed deterministic candidate-regression corpus with targeted positive, negative, edge, and "
            "multi-signal fixtures. Exact results validate only this corpus and are not a general-world accuracy claim."
        ),
        "metrics": metrics,
        "coverage": coverage,
        "per_rule": finalized_rules,
        "per_language": {key: _finalize_group(value) for key, value in sorted(per_language.items())},
        "per_difficulty": {key: _finalize_group(value) for key, value in sorted(per_difficulty.items())},
        "per_classification": {
            key: _finalize_group(value) for key, value in sorted(per_classification.items())
        },
        "limitations": manifest.get("limitations") or [],
        "cases": [asdict(result) for result in case_results],
    }


async def evaluate_remediation_manifest(manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("Remediation evaluation manifest schema_version must be 1")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Remediation evaluation manifest must declare cases")

    ids: set[str] = set()
    results: list[RemediationCaseResult] = []
    corpus_material: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="sentinel-remediation-eval-") as temporary:
        temporary_root = Path(temporary)
        for case in cases:
            case_id = case.get("id")
            if not case_id or case_id in ids:
                raise ValueError("Remediation cases contain a missing or duplicate id")
            ids.add(case_id)
            source_fixture = manifest_path.parent / case["source"]
            patch_fixture = manifest_path.parent / case["patch"]
            if not source_fixture.is_file() or not patch_fixture.is_file():
                raise ValueError(f"Remediation fixtures are missing for case {case_id}")

            case_root = temporary_root / case_id
            repository = case_root / "repository"
            patches_dir = case_root / "patches"
            workspace = case_root / "workspace"
            repository.mkdir(parents=True)
            expected_file = case["expected_file"]
            target = repository / expected_file
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_fixture, target)
            diff = patch_fixture.read_text(encoding="utf-8")

            validation = await validate_and_store_patch(
                repository,
                patches_dir,
                case_id,
                expected_file,
                diff,
                max_bytes=int(case.get("max_bytes", 64_000)),
                max_changed_lines=int(case.get("max_changed_lines", 200)),
            )
            observed_verification: str | None = None
            source_executed = False
            if validation.valid and validation.path is not None:
                finding = SimpleNamespace(
                    id=case_id,
                    rule_id=case["rule_id"],
                    file_path=expected_file,
                    line=int(case["line"]),
                    end_line=int(case["end_line"]),
                    language=case["language"],
                )
                proof = await verify_patch_regression(repository, workspace, finding, validation.path)
                observed_verification = proof.status
                source_executed = proof.source_executed

            expected_error = case.get("expected_error_contains")
            error_matches = True
            if expected_error:
                error_matches = expected_error.lower() in (validation.error or "").lower()
            passed = (
                validation.valid is bool(case["expected_patch_valid"])
                and observed_verification == case.get("expected_verification")
                and error_matches
                and source_executed is False
            )
            source_sha256 = _sha256_file(source_fixture)
            patch_sha256 = _sha256_file(patch_fixture)
            corpus_material.append(
                {
                    "case": case,
                    "source_sha256": source_sha256,
                    "patch_sha256": patch_sha256,
                }
            )
            results.append(
                RemediationCaseResult(
                    id=case_id,
                    rule_id=case["rule_id"],
                    language=case["language"],
                    difficulty=case["difficulty"],
                    expected_patch_valid=bool(case["expected_patch_valid"]),
                    observed_patch_valid=validation.valid,
                    expected_verification=case.get("expected_verification"),
                    observed_verification=observed_verification,
                    expected_error_contains=expected_error,
                    observed_error=validation.error,
                    source_sha256=source_sha256,
                    patch_sha256=patch_sha256,
                    source_executed=source_executed,
                    passed=passed,
                )
            )

    passed_cases = sum(item.passed for item in results)
    expected_accept = sum(item.expected_patch_valid for item in results)
    expected_reject = len(results) - expected_accept
    observed_accept = sum(item.observed_patch_valid for item in results)
    observed_reject = len(results) - observed_accept
    proof_expectations: dict[str, int] = defaultdict(int)
    proof_observed: dict[str, int] = defaultdict(int)
    per_difficulty: dict[str, dict[str, int]] = defaultdict(lambda: {"cases": 0, "passed": 0})
    for item in results:
        if item.expected_verification:
            proof_expectations[item.expected_verification] += 1
        if item.observed_verification:
            proof_observed[item.observed_verification] += 1
        per_difficulty[item.difficulty]["cases"] += 1
        per_difficulty[item.difficulty]["passed"] += int(item.passed)

    return {
        "schema_version": "sentinel-remediation-eval-v1",
        "corpus_version": manifest["corpus_version"],
        "corpus_sha256": _sha256_bytes(_canonical_bytes(corpus_material)),
        "scope": manifest["scope"],
        "metrics": {
            "case_count": len(results),
            "passed_cases": passed_cases,
            "failed_cases": len(results) - passed_cases,
            "case_pass_rate": _ratio(passed_cases, len(results)),
            "expected_patch_acceptances": expected_accept,
            "expected_patch_rejections": expected_reject,
            "observed_patch_acceptances": observed_accept,
            "observed_patch_rejections": observed_reject,
            "source_executed_cases": sum(item.source_executed for item in results),
        },
        "expected_proof_outcomes": dict(sorted(proof_expectations.items())),
        "observed_proof_outcomes": dict(sorted(proof_observed.items())),
        "per_difficulty": {
            key: {
                **value,
                "failed": value["cases"] - value["passed"],
                "pass_rate": _ratio(value["passed"], value["cases"]),
            }
            for key, value in sorted(per_difficulty.items())
        },
        "cases": [asdict(item) for item in results],
    }


async def evaluate_validation_pack(static_manifest: Path, remediation_manifest: Path) -> dict[str, Any]:
    static = evaluate_manifest(static_manifest)
    remediation = await evaluate_remediation_manifest(remediation_manifest)
    payload = {
        "schema_version": "sentinel-validation-pack-v1",
        "app_version": APP_VERSION,
        "ruleset_version": STATIC_RULESET_VERSION,
        "scope": (
            "Deterministic fixture validation for candidate rules, patch escrow, and non-executing regression proof. "
            "The results are reproducible corpus checks, not production security accuracy estimates."
        ),
        "metrics": static["metrics"],
        "static": static,
        "remediation": remediation,
        "limitations": static["limitations"],
    }
    payload["validation_pack_sha256"] = _sha256_bytes(_canonical_bytes(payload))
    return payload


def to_markdown(result: dict[str, Any]) -> str:
    static = result.get("static", result)
    remediation = result.get("remediation")
    metrics = static["metrics"]
    coverage = static.get("coverage", {})
    lines = [
        "# Sentinel validation pack",
        "",
        f"Ruleset: `{static['ruleset_version']}`",
        f"Static corpus: `{static.get('corpus_version', 'unknown')}`",
        f"Static corpus SHA-256: `{static.get('corpus_sha256', 'unknown')}`",
        "",
        static["scope"],
        "",
        "## Static candidate evaluation",
        "",
        "| Metric | Result |",
        "| --- | ---: |",
        f"| Cases | {metrics['case_count']} |",
        f"| Finding-bearing / negative cases | {metrics['positive_case_count']} / "
        f"{metrics['negative_case_count']} |",
        f"| Multi-signal subset | {metrics.get('multi_signal_case_count', 0)} |",
        f"| Edge or adversarial cases | {metrics.get('edge_case_count', 0)} |",
        f"| Exact case pass rate | {metrics['passed_cases']}/{metrics['case_count']} "
        f"({metrics['case_pass_rate']:.0%}) |",
        f"| True positives | {metrics['true_positives']} |",
        f"| Targeted true negatives | {metrics.get('targeted_true_negatives', 0)} |",
        f"| False positives | {metrics['false_positives']} |",
        f"| False negatives | {metrics['false_negatives']} |",
        f"| Micro precision | {metrics['precision']:.0%} |",
        f"| Micro recall | {metrics['recall']:.0%} |",
        f"| Targeted specificity | {metrics.get('specificity', 1.0):.0%} |",
        "",
        "## Coverage contract",
        "",
        "| Coverage | Result |",
        "| --- | ---: |",
        f"| Known rules | {coverage.get('known_rule_count', 0)} |",
        f"| Rules with positive support | {coverage.get('rules_with_positive_support', 0)} |",
        f"| Rules with negative support | {coverage.get('rules_with_negative_support', 0)} |",
        f"| Rules with edge support | {coverage.get('rules_with_edge_support', 0)} |",
        f"| Positive + negative coverage complete | {coverage.get('positive_and_negative_complete', False)} |",
        f"| Edge coverage complete | {coverage.get('edge_complete', False)} |",
        "",
        "## Per-language metrics",
        "",
        "| Language | Cases | Pass rate | TP | TN | FP | FN | Precision | Recall | Specificity |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for language, item in static.get("per_language", {}).items():
        lines.append(
            f"| {language} | {item['cases']} | {item['case_pass_rate']:.0%} | {item['tp']} | "
            f"{item['tn']} | {item['fp']} | {item['fn']} | {item['precision']:.0%} | "
            f"{item['recall']:.0%} | {item['specificity']:.0%} |"
        )

    lines.extend(
        [
            "",
            "## Per-rule coverage and confusion metrics",
            "",
            "| Rule | Family | + | - | Edge | TP | TN | FP | FN | Precision | Recall | Specificity |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for rule_id, item in static.get("per_rule", {}).items():
        lines.append(
            f"| `{rule_id}` | {item['family']} | {item['positive_cases']} | {item['negative_cases']} | "
            f"{item['edge_cases']} | {item['tp']} | {item['tn']} | {item['fp']} | {item['fn']} | "
            f"{item['precision']:.0%} | {item['recall']:.0%} | {item['specificity']:.0%} |"
        )

    if remediation:
        remediation_metrics = remediation["metrics"]
        lines.extend(
            [
                "",
                "## Patch escrow and regression proof evaluation",
                "",
                f"Remediation corpus: `{remediation['corpus_version']}`",
                f"Remediation corpus SHA-256: `{remediation['corpus_sha256']}`",
                "",
                "| Metric | Result |",
                "| --- | ---: |",
                f"| Cases | {remediation_metrics['case_count']} |",
                f"| Exact case pass rate | {remediation_metrics['passed_cases']}/"
                f"{remediation_metrics['case_count']} ({remediation_metrics['case_pass_rate']:.0%}) |",
                f"| Expected patch acceptances | {remediation_metrics['expected_patch_acceptances']} |",
                f"| Expected patch rejections | {remediation_metrics['expected_patch_rejections']} |",
                f"| Source-executed cases | {remediation_metrics['source_executed_cases']} |",
                "",
                "| Case | Expected patch | Observed patch | Expected proof | Observed proof | Status |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for case in remediation["cases"]:
            lines.append(
                f"| `{case['id']}` | {case['expected_patch_valid']} | {case['observed_patch_valid']} | "
                f"{case['expected_verification'] or 'none'} | {case['observed_verification'] or 'none'} | "
                f"{'PASS' if case['passed'] else 'FAIL'} |"
            )

    lines.extend(["", "## Explicit limitations", ""])
    for limitation in result.get("limitations", static.get("limitations", [])):
        lines.append(
            f"- **{limitation['id']}** (`{limitation['status']}`, {limitation['area']}): {limitation['detail']}"
        )

    lines.extend(
        [
            "",
            "## Static cases",
            "",
            "| Case | Class | Difficulty | Expected | Observed | Status |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for case in static["cases"]:
        expected = ", ".join(case["expected_rules"]) or "none"
        observed = ", ".join(case["observed_rules"]) or "none"
        lines.append(
            f"| `{case['id']}` | {case['classification']} | {case['difficulty']} | `{expected}` | "
            f"`{observed}` | {'PASS' if case['passed'] else 'FAIL'} |"
        )
    return "\n".join(lines) + "\n"
