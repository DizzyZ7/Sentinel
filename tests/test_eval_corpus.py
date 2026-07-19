import json
from pathlib import Path

import pytest

from app.services.evaluation import (
    evaluate_manifest,
    evaluate_remediation_manifest,
    evaluate_validation_pack,
    to_markdown,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "evals" / "manifest.json"
REMEDIATION_MANIFEST = ROOT / "evals" / "remediation" / "manifest.json"


def test_eval_manifest_is_unique_complete_and_taxonomized() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    ids = [case["id"] for case in manifest["cases"]]
    filenames = [case["filename"] for case in manifest["cases"]]
    rule_ids = [rule["id"] for rule in manifest["rules"]]

    assert manifest["schema_version"] == 2
    assert len(ids) == 60
    assert len(rule_ids) == 19
    assert len(ids) == len(set(ids))
    assert len(filenames) == len(set(filenames))
    assert len(rule_ids) == len(set(rule_ids))
    assert all((MANIFEST.parent / "cases" / filename).is_file() for filename in filenames)
    assert all(case["target_rules"] for case in manifest["cases"])
    assert {case["difficulty"] for case in manifest["cases"]} == {"basic", "edge", "adversarial"}
    assert {case["classification"] for case in manifest["cases"]} == {
        "positive",
        "negative",
        "multi_signal",
    }
    assert len(manifest["limitations"]) >= 5


def test_static_validation_has_full_rule_support_and_no_regressions() -> None:
    result = evaluate_manifest(MANIFEST)
    metrics = result["metrics"]
    coverage = result["coverage"]

    assert result["schema_version"] == "sentinel-static-eval-v2"
    assert len(result["corpus_sha256"]) == 64
    assert metrics["case_count"] == 60
    assert metrics["positive_case_count"] == 37
    assert metrics["negative_case_count"] == 23
    assert metrics["multi_signal_case_count"] == 2
    assert metrics["edge_case_count"] == 33
    assert metrics["true_positives"] == 39
    assert metrics["targeted_true_negatives"] == 23
    assert metrics["failed_cases"] == 0
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["specificity"] == 1.0
    assert coverage["known_rule_count"] == 19
    assert coverage["positive_and_negative_complete"] is True
    assert coverage["edge_complete"] is True
    assert coverage["missing_positive_support"] == []
    assert coverage["missing_negative_support"] == []
    assert coverage["missing_edge_support"] == []
    assert all(item["positive_cases"] >= 1 for item in result["per_rule"].values())
    assert all(item["negative_cases"] >= 1 for item in result["per_rule"].values())
    assert all(item["edge_cases"] >= 1 for item in result["per_rule"].values())


@pytest.mark.asyncio
async def test_remediation_validation_covers_accept_reject_and_proof_outcomes() -> None:
    result = await evaluate_remediation_manifest(REMEDIATION_MANIFEST)
    metrics = result["metrics"]

    assert result["schema_version"] == "sentinel-remediation-eval-v1"
    assert len(result["corpus_sha256"]) == 64
    assert metrics["case_count"] == 17
    assert metrics["passed_cases"] == 17
    assert metrics["failed_cases"] == 0
    assert metrics["expected_patch_acceptances"] == 7
    assert metrics["expected_patch_rejections"] == 10
    assert metrics["observed_patch_acceptances"] == 7
    assert metrics["observed_patch_rejections"] == 10
    assert metrics["source_executed_cases"] == 0
    assert result["expected_proof_outcomes"] == {"failed": 2, "inconclusive": 1, "passed": 4}
    assert result["observed_proof_outcomes"] == result["expected_proof_outcomes"]
    assert {item["difficulty"] for item in result["cases"]} == {"basic", "edge", "adversarial"}


@pytest.mark.asyncio
async def test_validation_pack_is_hash_covered_and_markdown_discloses_limits() -> None:
    result = await evaluate_validation_pack(MANIFEST, REMEDIATION_MANIFEST)
    markdown = to_markdown(result)

    assert result["schema_version"] == "sentinel-validation-pack-v1"
    assert len(result["validation_pack_sha256"]) == 64
    assert result["metrics"] == result["static"]["metrics"]
    assert "not a general-world accuracy claim" in result["static"]["scope"]
    assert "## Explicit limitations" in markdown
    assert "javascript_patch_syntax" in markdown
    assert "Patch escrow and regression proof evaluation" in markdown
