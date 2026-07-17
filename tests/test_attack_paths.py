from types import SimpleNamespace

from app.services.attack_paths import build_attack_path_response, to_mermaid


def finding(**overrides):
    values = {
        "id": "f1",
        "rule_id": "PY_COMMAND_INJECTION",
        "title": "Command injection",
        "file_path": "app.py",
        "line": 12,
        "static_rationale": "Request data reaches os.system.",
        "llm_status": "completed",
        "confirmed": True,
        "severity": "critical",
        "explanation": "An attacker can execute shell commands.",
        "patch_valid": True,
        "patch_error": None,
        "decision": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_attack_path_exposes_evidence_chain() -> None:
    response = build_attack_path_response("scan-1", [finding()])
    path = response.paths[0]
    assert path.status == "patch_ready"
    assert path.attack_surface == "code_execution"
    assert [node.stage for node in path.nodes] == [
        "source",
        "triage",
        "sink",
        "verdict",
        "patch",
        "human",
    ]
    assert len(path.edges) == 5


def test_attack_path_tracks_dismissal_and_approval() -> None:
    dismissed = finding(id="f2", confirmed=False, severity=None, patch_valid=None)
    approved = finding(decision=SimpleNamespace(decision="approved"))
    response = build_attack_path_response("scan-1", [dismissed, approved])
    assert response.summary.dismissed == 1
    assert response.summary.approved == 1


def test_mermaid_export_uses_safe_generated_node_ids() -> None:
    response = build_attack_path_response("scan-1", [finding(title='Bad "title" <script>')])
    graph = to_mermaid(response)
    assert graph.startswith("flowchart LR")
    assert "<script>" not in graph
    assert "P1N0" in graph
