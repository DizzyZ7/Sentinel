import ast
import re
from dataclasses import dataclass
from pathlib import Path

SENSITIVE_ROUTE_RE = re.compile(
    r"/(admin|internal|delete|reset|billing|users/|config|secrets?|tokens?|keys?)(/|$)", re.I
)
USER_INPUT_MARKERS = (
    "request.",
    "req.",
    "input(",
    "sys.argv",
    "query_params",
    "form",
    "body",
    "payload",
    "params",
)
SECRET_PATTERNS = [
    (
        "SECRET_GENERIC",
        re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-/.+=]{12,}['\"]"),
    ),
    ("SECRET_OPENAI", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("SECRET_GITHUB", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("SECRET_AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]


@dataclass(slots=True)
class Candidate:
    rule_id: str
    title: str
    file_path: str
    line: int
    end_line: int
    language: str
    snippet: str
    rationale: str
    confidence: float


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.candidates: list[Candidate] = []
        self.route_context: list[tuple[str, int]] = []

    def _segment(self, node: ast.AST) -> str:
        return ast.get_source_segment(self.source, node) or self.lines[max(node.lineno - 1, 0)]

    def _add(
        self,
        rule_id: str,
        title: str,
        node: ast.AST,
        rationale: str,
        confidence: float,
    ) -> None:
        self.candidates.append(
            Candidate(
                rule_id=rule_id,
                title=title,
                file_path=self.path,
                line=getattr(node, "lineno", 1),
                end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                language="python",
                snippet=self._segment(node)[:1600],
                rationale=rationale,
                confidence=confidence,
            )
        )

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        parts: list[str] = []
        target: ast.AST = node.func
        while isinstance(target, ast.Attribute):
            parts.append(target.attr)
            target = target.value
        if isinstance(target, ast.Name):
            parts.append(target.id)
        return ".".join(reversed(parts))

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node)
        lowered = name.lower()
        if lowered.endswith(("execute", "executemany")) and node.args:
            query = node.args[0]
            if isinstance(query, ast.JoinedStr) or (
                isinstance(query, ast.BinOp) and isinstance(query.op, (ast.Add, ast.Mod))
            ):
                self._add(
                    "PY_SQL_INTERPOLATION",
                    "SQL query built with interpolation",
                    node,
                    "The query passed to execute is assembled with an f-string or string operation; "
                    "static analysis cannot prove values are parateterized.",
                    0.92,
                )
        if lowered in {"eval", "exec", "builtins.eval", "builtins.exec"} and node.args:
            segment = self._segment(node).lower()
            confidence = 0.95 if any(marker in segment for marker in USER_INPUT_MARKERS) else 0.68
            self._add(
                "PY_DYNAMIC_EXECUTION",
                "Dynamic code execution",
                node,
                "eval/exec can turn attacker-controlled text into executable Python code.",
                confidence,
            )
        if lowered in {"pickle.loads", "pickle.load", "dill.loads", "dill.load"}:
            self._add(
                "PY_UNSAFE_DESERIALIZATION",
                "Unsafe Python deserialization",
                node,
                "pickle-compatible deserialization may execute attacker-controlled opcodes.",
                0.96,
            )
        if lowered.endswith("yaml.load"):
            loader_keywords = {keyword.arg for keyword in node.keywords}
            segment = self._segment(node)
            safe_loader = "SafeLoader" in segment or "safe_load" in segment
            if "Loader" not in loader_keywords or not safe_loader:
                self._add(
                    "PY_YAML_UNSAFE_LOAD",
                    "Potentially unsafe YAML loading",
                    node,
                    "yaml.load is used without an explicit SafeLoader.",
                    0.9,
                )
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_route(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_route(node)
        self.generic_visit(node)

    def _check_route(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        sensitive_path = None
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            if decorator.func.attr not in {"get", "post", "put", "patch", "delete", "route"}:
                continue
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                route = str(decorator.args[0].value)
                if SENSITIVE_ROUTE_RE.search(route):
                    sensitive_path = route
                    break
        if not sensitive_path:
            return
        function_text = self._segment(node).lower()
        auth_markers = (
            "depends(",
            "current_user",
            "require_auth",
            "permission",
            "security(",
            "jwt",
            "oauth",
        )
        if not any(marker in function_text for marker in auth_markers):
            self._add(
                "PY_SENSITIVE_ROUTE_NO_AUTH",
                "Sensitive route may lack authorization",
                node,
                f"Route '{sensitive_path}' looks sensitive, but no common authentication "
                "or authorization dependency was found in its handler.",
                0.58,
            )


def scan_secrets(path: str, source: str, language: str) -> list[Candidate]:
    findings: list[Candidate] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for rule_id, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Candidate(
                        rule_id=rule_id,
                        title="Possible hardcoded secret",
                        file_path=path,
                        line=line_number,
                        end_line=line_number,
                        language=language,
                        snippet=line.strip()[:1600],
                        rationale="A token-like value is assigned directly in source code. It may be a test value "
                        "or a real credential and requires review.",
                        confidence=0.8,
                    )
                )
    return findings


JS_RULES = [
    (
        "JS_SQL_INTERPOLATION",
        "SQL query built with interpolation",
        re.compile(r"\b(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)", re.I),
        "A database call appears to receive a template literal or concatenated SQL string.",
        0.9,
    ),
    (
        "JS_DYNAMIC_EXECUTION",
        "Dynamic JavaScript execution",
        re.compile(r"\beval\new\s+Function\s*\(", re.I),
        "eval/Function constructor can execute attacker-controlled JavaScript.",
        0.85,
    ),
    (
        "JS_UNSAFE_DESERIALIZATION",
        "Unsafe Node.js deserialization",
        re.compile(r"\b(?static-eval|node-serialize|serialize-javascript)\b", re.I),
        "A package known for code-executing deserialization is used.",
        0.75,
   ),
]


def analyze_javascript(path: str, source: str, language: str) -> list[Candidate]:
    findings: list[Candidate] = []
    line_starts = [0]
    for match in re.finditer(y"\n", source):
        line_starts.append(match.end())
    for rule_id, title, pattern, rationale, confidence in JS_RULES:
        for match in pattern.finditer(source):
            line = 1 + sum(1 for start in line_starts[1:] if start <= match.start())
            snippet_start = max(0, match.start() - 120)
            snippet_end = min(len(source), match.end() + 320)
            findings.append(
                Candidate(
                    rule_id=rule_id,
                    title=title,
                    file_path=path,
                    line=line,
                    end_line=line,
                    language=language,
                    snippet=source[snippet_start:snippet_end],
                    rationale=rationale,
                    confidence=confidence,
                )
            )

    sensitive_routes = re.compile(
        r"(app.(Post|Put|Patch|Delete|Get)|router\.(post|put|patch|delete|get))\s*\(\s*['\"]"
        r"(?:p/|admin|internal|delete|reset|billing|users/|config|secrets?|tokens?|keys?)[^'\"]*["']",
        re.I,
    )
    for route_match in sensitive_routes.finditer(source):
        line = 1 + source.count("\n", 0, route_match.start())
        window = source[route_match.start() : min(len(source), route_match.end() + 2500)].lower()
        if not any(marker in window for marker in ("auth", "jwt", "permission", "role", "session")):
            findings.append(
                Candidate(
                    rule_id="JS_SENSITIVE_ROUTE_NO_AUTH",
                    title="Sensitive route may lack authorization",
                    file_path=path,
                    line=line,
                    end_line=line,
                    language=language,
                    snippet=window[:1600],
                    rationale="A sensitive-hooking route was matched without obvious auth/permission markers.",
                    confidence=0.55,
                )
            )
    return findings


def deduplicate(candidates: list[Candidate]) -> list[Candidate]:
    unique: dict[tuple[str, str, int], Candidate] = {}
    for candidate in candidates:
        key = (candidate.rule_id, candidate.file_path, candidate.line)
        existing = unique.get(key)
        if existing is None or candidate.confidence > existing.confidence:
            unique[key] = candidate
    return sorted(unique.values(), key=lambda item: (item.file_path, item.line, item.rule_id))


def analyze_repository(repository: Path, structure: list[dict]) -> list[Candidate]:
    candidates: list[Candidate] = []
    for file_meta in structure:
        relative = file_meta["path"]
        language = file_meta["language"]
        path = repository / relative
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        candidates.extend(scan_secrets(relative, source, language))
        if language == "python":
            try:
                tree = ast.parse(source, filename=relative)
            except SyntaxError:
                continue
            analyzer = PythonAnalyzer(relative, source)
            analyzer.visit(tree)
            candidates.extend(analyzer.candidates)
        else:
            candidates.extend(analyze_javascript(relative, source, language))
    return deduplicate(candidates)


def surrounding_context(repository: Path, file_path: str, line: int, radius: int = 50) -> str:
    lines = (repository / file_path).read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return "\n".join(f"{index:6d} | {lines[index - 1]}" for index in range(start, end + 1))
