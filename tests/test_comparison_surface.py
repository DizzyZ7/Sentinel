from pathlib import Path

from app.main import app


def test_comparison_routes_are_registered() -> None:
    routes = {(route.path, method) for route in app.routes for method in getattr(route, "methods", set())}
    assert ("/scan/{baseline_scan_id}/rescan", "POST") in routes
    assert ("/scan/{current_scan_id}/compare/{baseline_scan_id}", "GET") in routes


def test_comparison_and_judge_templates_include_baseline_workflow() -> None:
    root = Path(__file__).resolve().parents[1]
    comparison = (root / "app/templates/comparison.html").read_text(encoding="utf-8")
    judge = (root / "app/templates/judge.html").read_text(encoding="utf-8")
    assert "NO-NEW-RISK POLICY" in comparison
    assert "Introduced" in comparison
    assert "Start rescan" in judge
    assert "comparison_url" in judge
