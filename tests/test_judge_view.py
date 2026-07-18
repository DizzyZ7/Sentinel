from types import SimpleNamespace

from app.routers.judge import build_judge_metrics


def item(**changes):
    values = {
        "llm_status": "completed",
        "confirmed": True,
        "patch_valid": True,
        "verification": SimpleNamespace(status="passed"),
        "decision": None,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def test_judge_metrics_cover_three_outcomes() -> None:
    metrics = build_judge_metrics(
        [
            item(),
            item(confirmed=False, patch_valid=None, verification=None),
            item(verification=SimpleNamespace(status="failed")),
        ]
    )
    assert metrics["review_coverage"] == 100
    assert metrics["confirmed"] == 2
    assert metrics["dismissed"] == 1
    assert metrics["valid_patches"] == 2
    assert metrics["proof_passed"] == 1
    assert metrics["proof_failed"] == 1
