import ast
import re
from dataclasses import dataclass
from pathlib import Path

SENSITIVE_ROUTE_RE = re.compile(
    r"/(admin|internal|delete|reset|billing|users?|config|secrets?|tokens?|keys?)(/|$)", re.I
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
    "cookies",
    "headers",
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
        self.tainted_names: set[str] = set()
        self.interpolated_names: set[str] = set()

    def _segment(self, node: ast.AST) -> str:
        return ast.get_source_segment(self.source, node) or self.lines[max(getattr(node, "lineno", 1) - 1, 0)]

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

    @staticmethod
    def _target_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, ast.Tuple | ast.List):
            names: set[str] = set()
            for item in target.elts:
                names.update(PythonAnalyzer._target_names(item))
            return names
        return set()

    def _is_user_controlled(self, node: ast.AST) -> bool:
        segment = self._segment(node).lower()
        if any(marker in segment for marker in USER_INPUT_MARKERS):
            return True
        return any(isinstance(item, ast.Name) and item.id in self.tainted_names for item in ast.walk(node))

    def _is_interpolated(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            return True
        return isinstance(node, ast.Name) and node.id in self.interpolated_names

    def _track_assignment(self, target: ast.AST, value: ast.AST) -> None:
        names = self._target_names(target)
        if self._is_user_controlled(value):
            self.tainted_names.update(names)
        if self._is_interpolated(value):
            self.interpolated_names.update(names)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._track_assignment(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._track_assignment(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._track_assignment(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node)
        lowered = name.lower()
        first_arg = node.args[0] if node.args else None

        if lowered.endswith(("execute", "executemany")) and first_arg is not None and self._is_interpolated(first_arg):
            confidence = 0.96 if self._is_user_controlled(first_arg) else 0.84
            self._add(
                "PY_SQL_INTERPOLATION",
                "SQL query built with interpolation",
                node,
                "The query passed to the database is assembled with an f-string or string operation instead of "
                "a parameterized query.",
                confidence,
            )

        if lowered in {"eval", "exec", "builtins.eval", "builtins.exec"} and first_arg is not None:
            confidence = 0.98 if self._is_user_controlled(first_arg) else 0.68
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

        command_calls = {
            "os.system",
            "os.popen",
            "subprocess.run",
            "subprocess.call",
            "subprocess.popen",
            "subprocess.check_output",
            "subprocess.check_call",
        }
        if lowered in command_calls and first_arg is not None:
            shell_true = any(
                keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                for keyword in node.keywords
            )
            if self._is_user_controlled(first_arg) and (lowered.startswith("os.") or shell_true):
                self._add(
                    "PY_COMMAND_INJECTION",
                    "User-controlled operating-system command",
                    node,
                    "Request-derived data appears to reach a shell-capable command execution API.",
                    0.97,
                )

        path_calls = {"open", "builtins.open", "send_file", "flask.send_file", "fileresponse"}
        if lowered in path_calls and first_arg is not None and self._is_user_controlled(first_arg):
            self._add(
                "PY_PATH_TRAVERSAL",
                "User-controlled filesystem path",
                node,
                "A request-derived path reaches a file read or file response API "
                "without an obvious boundary check.",
                0.86,
            )

        network_calls = {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            "requests.request",
            "httpx.get",
            "httpx.post",
            "httpx.request",
            "urllib.request.urlopen",
        }
        if lowered in network_calls and first_arg is not None and self._is_user_controlled(first_arg):
            self._add(
                "PY_SSRF",
                "User-controlled outbound request",
                node,
                "A request-derived URL appears to reach an outbound HTTP client and may enable SSRF.",
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
        re.compile(r"\b(?:eval|Function)\s*\([^\n]*(?:req\.|request\.|body|query|params)", re.I),
        "eval or Function appears to consume request-derived data.",
        0.95,
    ),
    (
        "JS_COMMAND_INJECTION",
        "User-controlled operating-system command",
        re.compile(
            r"\b(?:child_process\.)?(?:exec|execSync)\s*\([^\n]*(?:req\.|request\.|body|query|params)", re.I
        ),
        "Request-derived data appears to reach a shell command execution API.",
        0.97,
    ),
    (
        "JS_PATH_TRAVERSAL",
        "User-controlled filesystem path",
        re.compile(
            r"\b(?:fs\.)?(?:readFile|readFileSync|createReadStream|sendFile)\s*\([^\n]*(?:req\.|request\.|params|query|body)",
            re.I,
        ),
        "A request-derived path reaches a filesystem API without an obvious boundary check.",
        0.86,
    ),
    (
        "JS_SSRF",
        "User-controlled outbound request",
        re.compile(
            r"\b(?:fetch|axios\.(?:get|post)|https?\.get)\s*\([^\n]*"
            r"(?:req\.|request\.|params|query|body)",
            re.I,
        ),
        "A request-derived URL appears to reach an outbound HTTP client and may enable SSRF.",
        0.9,
    ),
    (
        "JS_YAML_UNSAFE_LOAD",
        "Potentially unsafe YAML loading",
        re.compile(r"\b(?:yaml|jsyaml)\.load\s*\(", re.I),
        "YAML parsing is a review candidate; schema validation and safe parser behavior should be confirmed.",
        0.55,
    ),
]

EXPRESS_ROUTE_RE = re.compile(
    r"\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['\"](?P<path>[^'\"]+)['\"](?P<tail>[^\n;]*)",
    re.I,
)


def analyze_javascript(path: str, source: str, language: str) -> list[Candidate]:
    candidates: list[Candidate] = []
    lines = source.splitlines()
    for rule_id, title, pattern, rationale, confidence in JS_RULES:
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            candidates.append(
                Candidate(
                    rule_id=rule_id,
                    title=title,
                    file_path=path,
                    line=line,
                    end_line=line,
                    language=language,
                    snippet=lines[line - 1].strip()[:1600],
                    rationale=rationale,
                    confidence=confidence,
                )
            )
    for match in EXPRESS_ROUTE_RE.finditer(source):
        route = match.group("path")
        tail = match.group("tail").lower()
        if SENSITIVE_ROUTE_RE.search(route) and not any(
            marker in tail for marker in ("auth", "permission", "authorize", "jwt", "session")
        ):
            line = source.count("\n", 0, match.start()) + 1
            candidates.append(
                Candidate(
                    rule_id="JS_SENSITIVE_ROUTE_NO_AUTH",
                    title="Sensitive route may lack authorization",
                    file_path=path,
                    line=line,
                    end_line=line,
                    language=language,
                    snippet=lines[line - 1].strip()[:1600],
                    rationale=(
                        f"Route '{route}' looks sensitive, but no obvious auth middleware appears before the handler."
                    ),
                    confidence=0.58,
                )
            )
    return candidates


def analyze_repository(repository: Path, structure: list[dict]) -> list[Candidate]:
    candidates: list[Candidate] = []
    for item in structure:
        relative = item["path"]
        language = item["language"]
        path = repository / relative
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        candidates.extend(scan_secrets(relative, source, language))
        if language == "python":
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            analyzer = PythonAnalyzer(relative, source)
            analyzer.visit(tree)
            candidates.extend(analyzer.candidates)
        else:
            candidates.extend(analyze_javascript(relative, source, language))

    unique: dict[tuple[str, str, int], Candidate] = {}
    for candidate in candidates:
        unique[(candidate.rule_id, candidate.file_path, candidate.line)] = candidate
    return sorted(unique.values(), key=lambda finding: (finding.file_path, finding.line, finding.rule_id))


def surrounding_context(repository: Path, file_path: str, line: int, radius: int = 50) -> str:
    lines = (repository / file_path).read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    return "\n".join(f"{index + 1:>5} | {lines[index]}" for index in range(start, end))
