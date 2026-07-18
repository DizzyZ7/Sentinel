import json
from pathlib import Path

from scripts.run_evals import DEFAULT_MANIFEST, evaluate_manifest


def test_eval_manifest_is_unique_and_complete() -> None:
    manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    ids = [case["id"] for case in manifest["cases"]]
    filenames = [case["filename"] for case in manifest["cases"]]

    assert manifest["schema_version"] == 1
    assert len(ids) == 20
    assert len(ids) == len(set(ids))
    assert len(filenames) == len(set(filenames))
    assert all((DEFAULT_MANIFEST.parent / "cases" / filename).is_file() for filename in filenames)


def test_curated_static_eval_has_no_regressions() -> None:
    result = evaluate_manifest(Path(DEFAULT_MANIFEST))
    metrics = result["metrics"]

    assert metrics["case_count"] == 20
    assert metrics["positive_case_count"] == 15
    assert metrics["negative_case_count"] == 5
    assert metrics["failed_cases"] == 0
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
