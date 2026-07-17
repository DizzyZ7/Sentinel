from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from app.models.finding import Finding
from app.schemas.attack_path import (
    AttackPath,
    AttackPathEdge,
    AttackPathNode,
    AttackPathResponse,
    AttackPathSummary,
)


@dataclass(frozen=True, slots=True)
class RuleProfile:
    source: str
    source_detail: str
    sink: str
    sink_detail: str
    attack_surface: str


DEFAULT_PROFILE = RuleProfile(
    source="Repository-controlled data",
    source_detail="The deterministic scanner identified data or configuration that may cross a trust boundary.",
    sink="Sensitive operation",
    sink_detail="The candidate reaches an operation whose security properties require contextual review.",
    attack_surface="application",
)

RULE_PROFILES: tuple[tuple[str, RuleProfile], ...] = (
    (
        "SQL_INTERPOLATION",
        RuleProfile(
            "Request-derived value",
            "Untrusted input appears in dynamically assembled query text.",
            "Database query engine",
            "The resulting string is passed to a SQL execution API.",
            "data",
        ),
    ),
    (
        "DYNAMIC_EXECUTION",
        RuleProfile(
            "Untrusted expression",
            "Request-like data can influence executable source text.",
            "Language runtime",
            "eval, exec, or Function interprets the value as code.",
            "code_execution",
        ),
    ),
    (
        "UNSAFE_DESERIALIZATION",
        RuleProfile(
            "Serialized payload",
            "A payload may be controlled outside the current trust boundary.",
            "Object deserializer",
            "The deserializer can instantiate objects or execute gadget behavior.",
            "code_execution",
        ),
    ),
    (
        "YAML_UNSAFE_LOAD",
        RuleProfile(
            "YAML document",
            "YAML content may originate from an untrusted caller or file.",
            "Unsafe YAML loader",
            "The selected loader may construct unsafe Python objects.",
            "code_execution",
        ),
    ),
    (
        "SENSITIVE_ROUTE_NO_AUTH",
        RuleProfile(
            "Unauthenticated HTTP request",
            "The route is reachable without an obvious identity or permission check.",
            "Sensitive route handler",
            "Administrative, billing, user, token, or configuration behavior may be exposed.",
            "authorization",
        ),
    ),
    (
        "COMMAND_INJECTION",
        RuleProfile(
            "Request-controlled command",
            "External input appears to influence a command string.",
            "Operating-system shell",
            "A shell-capable API can interpret metacharacters and execute additional commands.",
            "code_execution",
        ),
    ),
    (
        "PATH_TRAVERSAL",
        RuleProfile(
            "Request-controlled path",
            "External input appears to influence a filesystem path.",
            "Filesystem boundary",
            "A file API may read outside the intended directory.",
            "filesystem",
        ),
    ),
    (
        "SSRF",
        RuleProfile(
            "Request-controlled URL",
            "External input appears to determine an outbound destination.",
            "Server-side HTTP client",
            "The server may reach internal services, metadata endpoints, or unexpected hosts.",
            "network",
        ),
    ),
    (
        "SECRET",
        RuleProfile(
            "Credential in source",
            "A token-like value is embedded in a repository artifact.",
            "Build and distribution pipeline",
            "Source distribution can expose the credential to clones, logs, caches, or images.",
            "secrets",
        ),
    ),
)


def _profile(rule_id: str) -> RuleProfile:
    return next((profile for marker, profile in RULE_PROFILES if marker in rule_id), DEFAULT_PROFILE)


def _path_status(finding: Finding) -> str:
    if finding.llm_status in {"pending", "failed", "skipped"}:
        return "unreviewed"
    if not finding.confirmed:
        return "dismissed"
    if finding.decision:
        return "approved" if finding.decision.decision == "approved" else "rejected"
    if finding.patch_valid:
        return "patch_ready"
    return "exposed"


def _node_statuses(finding: Finding, path_status: str) -> dict[str, str]:
    verdict = "neutral"
    if path_status == "dismissed":
        verdict = "safe"
    elif path_status == "unreviewed":
        verdict = "warning"
    elif finding.confirmed:
        verdict = "danger"

    patch = "neutral"
    if finding.confirmed:
        patch = "safe" if finding.patch_valid else "warning"

    human = "neutral"
    if path_status == "approved":
        human = "safe"
    elif path_status == "rejected":
        human = "blocked"
    elif finding.confirmed:
        human = "warning"

    return {
        "source": "danger" if finding.confirmed else "neutral",
        "triage": "warning",
        "sink": "danger" if finding.confirmed else "neutral",
        "verdict": verdict,
        "patch": patch,
        "human": human,
    }


def _build_path(finding: Finding) -> AttackPath:
    profile = _profile(finding.rule_id)
    status = _path_status(finding)
    statuses = _node_statuses(finding, status)
    prefix = finding.id
    verdict_detail = {
        "dismissed": "GPT-5.6 rejected the static candidate using the supplied local evidence.",
        "unreviewed": f"Deep review is {finding.llm_status}; the candidate remains unresolved.",
    }.get(status, finding.explanation or "GPT-5.6 confirmed the candidate as a real security finding.")
    patch_detail = (
        "The proposed unified diff passed path restrictions, git apply --check, and language validation."
        if finding.patch_valid
        else finding.patch_error or "No validated patch is available yet."
    )
    human_detail = (
        f"A reviewer recorded: {finding.decision.decision}."
        if finding.decision
        else "A human reviewer has not recorded a final decision."
    )

    nodes = [
        AttackPathNode(
            id=f"{prefix}:source",
            stage="source",
            label=profile.source,
            detail=profile.source_detail,
            status=statuses["source"],
        ),
        AttackPathNode(
            id=f"{prefix}:triage",
            stage="triage",
            label="Deterministic evidence",
            detail=f"{finding.rule_id} at {finding.file_path}:{finding.line}. {finding.static_rationale}",
            status=statuses["triage"],
        ),
        AttackPathNode(
            id=f"{prefix}:sink",
            stage="sink",
            label=profile.sink,
            detail=profile.sink_detail,
            status=statuses["sink"],
        ),
        AttackPathNode(
            id=f"{prefix}:verdict",
            stage="verdict",
            label="GPT-5.6 verdict",
            detail=verdict_detail,
            status=statuses["verdict"],
        ),
        AttackPathNode(
            id=f"{prefix}:patch",
            stage="patch",
            label="Patch escrow",
            detail=patch_detail,
            status=statuses["patch"],
        ),
        AttackPathNode(
            id=f"{prefix}:human",
            stage="human",
            label="Human decision",
            detail=human_detail,
            status=statuses["human"],
        ),
    ]
    edges = [
        AttackPathEdge(source=nodes[0].id, target=nodes[1].id, label="observed as"),
        AttackPathEdge(source=nodes[1].id, target=nodes[2].id, label="reaches"),
        AttackPathEdge(source=nodes[2].id, target=nodes[3].id, label="reviewed by"),
        AttackPathEdge(source=nodes[3].id, target=nodes[4].id, label="mitigated by"),
        AttackPathEdge(source=nodes[4].id, target=nodes[5].id, label="requires"),
    ]
    return AttackPath(
        id=f"path:{finding.id}",
        finding_id=finding.id,
        title=finding.title,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        line=finding.line,
        severity=finding.severity,
        status=status,
        attack_surface=profile.attack_surface,
        nodes=nodes,
        edges=edges,
    )


def build_attack_path_response(scan_id: str, findings: Iterable[Finding]) -> AttackPathResponse:
    paths = [_build_path(finding) for finding in findings]
    counts = Counter(path.status for path in paths)
    return AttackPathResponse(
        scan_id=scan_id,
        summary=AttackPathSummary(
            total=len(paths),
            exposed=counts["exposed"],
            patch_ready=counts["patch_ready"],
            approved=counts["approved"],
            rejected=counts["rejected"],
            dismissed=counts["dismissed"],
            unreviewed=counts["unreviewed"],
        ),
        paths=paths,
    )


def to_mermaid(response: AttackPathResponse) -> str:
    def clean(value: str) -> str:
        return (
            value.replace('"', "'")
            .replace("<", "(")
            .replace(">", ")")
            .replace("\n", " ")[:100]
        )

    lines = ["flowchart LR"]
    for index, path in enumerate(response.paths, start=1):
        lines.append(f"  subgraph P{index}[\"{clean(path.title)}\"]")
        for node_index, node in enumerate(path.nodes):
            node_id = f"P{index}N{node_index}"
            lines.append(f"    {node_id}[\"{clean(node.label)}\"]")
        for edge_index, edge in enumerate(path.edges):
            lines.append(
                f"    P{index}N{edge_index} -->|{clean(edge.label)}| P{index}N{edge_index + 1}"
            )
        lines.append("  end")
    return "\n".join(lines) + "\n"
