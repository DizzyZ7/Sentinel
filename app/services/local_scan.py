from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from pathspec import PathSpec

from app.core.version import APP_VERSION, STATIC_RULESET_VERSION
from app.services.context_sanitizer import sanitize_context
from app.services.source_types import IGNORED_DIRS, SUPPORTED_EXTENSIONS
from app.services.static_analysis import Candidate, analyze_repository

LOCAL_SCAN_SCHEMA_VERSION = "sentinel-local-scan-v1"
LOCAL_FINGERPRINT_VERSION = "sentinel-local-fingerprint-v1"
EXIT_OK = 0
EXIT_POLICY_BLOCK = 1
EXIT_CONFIGURATION = 2
EXIT_SCAN_ERROR = 3

FailOn = Literal["never", "any", "new"]


class LocalScanError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LocalFile:
    path: str
    language: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    files: tuple[LocalFile, ...]
    skipped: dict[str, int]
    git_root: str | None
    scope: str


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _run_git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ASKPASS": "/bin/false",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "core.fsmonitor=false",
            "-c",
            "diff.external=",
            *args,
        ],
        capture_output=True,
        check=False,
        timeout=20,
        env=env,
    )
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()[-800:]
        raise LocalScanError(f"git {' '.join(args)} failed: {detail or f'exit {result.returncode}'}")
    return result


def _git_context(root: Path) -> tuple[Path, str] | None:
    try:
        result = _run_git(root, "rev-parse", "--show-toplevel", check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    git_root = Path(result.stdout.decode("utf-8", "replace").strip()).resolve()
    try:
        scope = root.resolve().relative_to(git_root).as_posix()
    except ValueError:
        return None
    return git_root, scope or "."


def _decode_nul_paths(value: bytes) -> set[str]:
    return {
        item.decode("utf-8", "surrogateescape").replace("\\", "/")
        for item in value.split(b"\0")
        if item
    }


def _git_candidates(root: Path, changed_only: bool, base_ref: str | None) -> tuple[Path, str, set[str]] | None:
    context = _git_context(root)
    if context is None:
        if changed_only:
            raise LocalScanError("--changed-only requires a Git work tree")
        return None
    git_root, scope = context
    pathspec = ["--", scope]

    if not changed_only:
        result = _run_git(git_root, "ls-files", "-co", "--exclude-standard", "-z", *pathspec)
        return git_root, scope, _decode_nul_paths(result.stdout)

    selected: set[str] = set()
    head = _run_git(git_root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", check=False)
    has_head = head.returncode == 0

    if base_ref:
        verified = _run_git(
            git_root,
            "rev-parse",
            "--verify",
            "--quiet",
            f"{base_ref}^{{commit}}",
            check=False,
        )
        if verified.returncode != 0:
            raise LocalScanError(f"Base ref is not available locally: {base_ref}")
        if not has_head:
            raise LocalScanError("A base ref cannot be compared before the repository has a HEAD commit")
        committed = _run_git(
            git_root,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            f"{base_ref}...HEAD",
            *pathspec,
        )
        selected.update(_decode_nul_paths(committed.stdout))
    elif has_head:
        working = _run_git(
            git_root,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            "HEAD",
            *pathspec,
        )
        selected.update(_decode_nul_paths(working.stdout))

    if has_head and base_ref:
        working = _run_git(
            git_root,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            "HEAD",
            *pathspec,
        )
        selected.update(_decode_nul_paths(working.stdout))

    untracked = _run_git(git_root, "ls-files", "--others", "--exclude-standard", "-z", *pathspec)
    selected.update(_decode_nul_paths(untracked.stdout))
    if not has_head:
        tracked = _run_git(git_root, "ls-files", "-c", "-z", *pathspec)
        selected.update(_decode_nul_paths(tracked.stdout))
    return git_root, scope, selected


def _root_ignore_spec(root: Path) -> PathSpec | None:
    ignore_file = root / ".gitignore"
    if not ignore_file.is_file():
        return None
    try:
        lines = ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return PathSpec.from_lines("gitwildmatch", lines)


def _fallback_candidates(root: Path) -> set[str]:
    spec = _root_ignore_spec(root)
    paths: set[str] = set()
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for directory in directories:
            candidate = current_path / directory
            relative = candidate.relative_to(root).as_posix()
            ignored = directory in IGNORED_DIRS or candidate.is_symlink()
            if not ignored and spec:
                ignored = spec.match_file(f"{relative}/")
            if not ignored:
                kept_directories.append(directory)
        directories[:] = kept_directories

        for filename in filenames:
            path = current_path / filename
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if spec and spec.match_file(relative):
                continue
            paths.add(relative)
    return paths


def _is_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:8192]
    except OSError:
        return True
    if b"\0" in sample:
        return True
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def discover_local_files(
    root: Path,
    *,
    changed_only: bool = False,
    base_ref: str | None = None,
    max_file_bytes: int = 1_000_000,
    max_files: int = 5_000,
) -> DiscoveryResult:
    if max_file_bytes < 1:
        raise LocalScanError("max_file_bytes must be positive")
    if max_files < 1:
        raise LocalScanError("max_files must be positive")

    root = root.expanduser().resolve()
    if not root.exists():
        raise LocalScanError(f"Scan path does not exist: {root}")
    if not root.is_dir():
        raise LocalScanError("Sentinel local scan currently requires a directory")

    git_selection = _git_candidates(root, changed_only, base_ref)
    if git_selection:
        git_root, scope, selected = git_selection
        selected_pairs = []
        for repository_path in selected:
            absolute = git_root / repository_path
            try:
                relative = absolute.relative_to(root).as_posix()
            except ValueError:
                continue
            selected_pairs.append((relative, absolute))
    else:
        git_root = None
        scope = "."
        selected_pairs = [(relative, root / relative) for relative in _fallback_candidates(root)]

    skipped = {
        "missing": 0,
        "symlink": 0,
        "ignored_directory": 0,
        "unsupported_extension": 0,
        "oversized": 0,
        "binary_or_non_utf8": 0,
    }
    files: list[LocalFile] = []
    for relative, absolute in sorted(selected_pairs, key=lambda item: item[0]):
        if any(part in IGNORED_DIRS for part in Path(relative).parts):
            skipped["ignored_directory"] += 1
            continue
        if absolute.is_symlink():
            skipped["symlink"] += 1
            continue
        if not absolute.exists() or not absolute.is_file():
            skipped["missing"] += 1
            continue
        language = SUPPORTED_EXTENSIONS.get(absolute.suffix.lower())
        if not language:
            skipped["unsupported_extension"] += 1
            continue
        try:
            size = absolute.stat().st_size
        except OSError:
            skipped["missing"] += 1
            continue
        if size > max_file_bytes:
            skipped["oversized"] += 1
            continue
        if _is_binary(absolute):
            skipped["binary_or_non_utf8"] += 1
            continue
        try:
            digest = _sha256_bytes(absolute.read_bytes())
        except OSError:
            skipped["missing"] += 1
            continue
        files.append(LocalFile(path=relative, language=language, size=size, sha256=digest))
        if len(files) > max_files:
            raise LocalScanError(f"Supported file count exceeds configured limit: {max_files}")

    return DiscoveryResult(
        files=tuple(files),
        skipped=skipped,
        git_root=str(git_root) if git_root else None,
        scope=scope,
    )


def candidate_fingerprint(candidate: Candidate) -> str:
    normalized_snippet = " ".join(candidate.snippet.split())
    canonical = "\0".join(
        [
            LOCAL_FINGERPRINT_VERSION,
            candidate.rule_id,
            candidate.file_path.replace("\\", "/").lower(),
            candidate.language.lower(),
            normalized_snippet,
        ]
    )
    return _sha256_bytes(canonical.encode("utf-8"))


def _load_baseline(path: Path | None) -> tuple[set[str], str | None]:
    if path is None:
        return set(), None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalScanError(f"Could not read baseline report: {exc}") from exc
    if payload.get("schema_version") != LOCAL_SCAN_SCHEMA_VERSION:
        raise LocalScanError("Baseline is not a Sentinel local scan v1 report")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise LocalScanError("Baseline report has no findings array")
    fingerprints = {
        str(item["fingerprint"])
        for item in findings
        if isinstance(item, dict) and isinstance(item.get("fingerprint"), str)
    }
    report_sha = payload.get("report_sha256")
    return fingerprints, str(report_sha) if report_sha else None


def _finding_payload(
    candidate: Candidate,
    source_sha256: str,
    baseline_fingerprints: set[str],
    *,
    include_snippets: bool,
) -> dict[str, Any]:
    fingerprint = candidate_fingerprint(candidate)
    sanitized = sanitize_context(candidate.snippet)
    payload: dict[str, Any] = {
        "fingerprint_version": LOCAL_FINGERPRINT_VERSION,
        "fingerprint": fingerprint,
        "baseline_state": "existing" if fingerprint in baseline_fingerprints else "new",
        "rule_id": candidate.rule_id,
        "title": candidate.title,
        "file_path": candidate.file_path,
        "line": candidate.line,
        "end_line": candidate.end_line,
        "language": candidate.language,
        "static_rationale": candidate.rationale,
        "static_confidence": candidate.confidence,
        "source_sha256": source_sha256,
        "redaction_count": len(sanitized.redactions),
        "confirmed": False,
        "review_state": "deterministic_candidate",
    }
    if include_snippets:
        payload["snippet"] = sanitized.text
    return payload


def _policy_result(
    findings: list[dict[str, Any]],
    *,
    fail_on: FailOn,
    fail_confidence: float,
) -> dict[str, Any]:
    eligible = [item for item in findings if float(item["static_confidence"]) >= fail_confidence]
    if fail_on == "new":
        blockers = [item for item in eligible if item["baseline_state"] == "new"]
    elif fail_on == "any":
        blockers = eligible
    else:
        blockers = []
    return {
        "fail_on": fail_on,
        "fail_confidence": fail_confidence,
        "blocked": bool(blockers),
        "exit_code": EXIT_POLICY_BLOCK if blockers else EXIT_OK,
        "blocker_count": len(blockers),
        "blocker_fingerprints": [item["fingerprint"] for item in blockers],
    }


def build_local_scan_report(
    root: Path,
    *,
    changed_only: bool = False,
    base_ref: str | None = None,
    baseline: Path | None = None,
    min_confidence: float = 0.0,
    fail_on: FailOn = "never",
    fail_confidence: float = 0.8,
    max_file_bytes: int = 1_000_000,
    max_files: int = 5_000,
    include_snippets: bool = True,
) -> dict[str, Any]:
    if not 0 <= min_confidence <= 1:
        raise LocalScanError("min_confidence must be between 0 and 1")
    if not 0 <= fail_confidence <= 1:
        raise LocalScanError("fail_confidence must be between 0 and 1")
    if base_ref and not changed_only:
        raise LocalScanError("--base-ref is only valid together with --changed-only")

    resolved_root = root.expanduser().resolve()
    discovery = discover_local_files(
        resolved_root,
        changed_only=changed_only,
        base_ref=base_ref,
        max_file_bytes=max_file_bytes,
        max_files=max_files,
    )
    structure = [
        {"path": item.path, "language": item.language, "size": item.size}
        for item in discovery.files
    ]
    candidates = analyze_repository(resolved_root, structure)
    candidates = [item for item in candidates if item.confidence >= min_confidence]
    baseline_fingerprints, baseline_report_sha = _load_baseline(baseline)
    file_hashes = {item.path: item.sha256 for item in discovery.files}
    findings = [
        _finding_payload(
            candidate,
            file_hashes[candidate.file_path],
            baseline_fingerprints,
            include_snippets=include_snippets,
        )
        for candidate in candidates
    ]
    current_fingerprints = {item["fingerprint"] for item in findings}
    new_count = sum(item["baseline_state"] == "new" for item in findings)
    existing_count = len(findings) - new_count
    comparison_scope = "partial" if changed_only else "complete"
    resolved_count: int | None = None
    if baseline is not None and not changed_only:
        resolved_count = len(baseline_fingerprints - current_fingerprints)

    policy = _policy_result(findings, fail_on=fail_on, fail_confidence=fail_confidence)
    report: dict[str, Any] = {
        "schema_version": LOCAL_SCAN_SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "ruleset_version": STATIC_RULESET_VERSION,
        "repository": resolved_root.name,
        "mode": {
            "changed_only": changed_only,
            "base_ref": base_ref,
            "git_work_tree": discovery.git_root is not None,
            "git_scope": discovery.scope,
        },
        "safety": {
            "source_executed": False,
            "dependencies_installed": False,
            "patches_applied": False,
            "symlinks_followed": False,
            "snippets_secret_sanitized": True,
        },
        "inventory": {
            "selected_file_count": len(discovery.files),
            "selected_bytes": sum(item.size for item in discovery.files),
            "skipped": discovery.skipped,
            "files": [asdict(item) for item in discovery.files],
        },
        "baseline": {
            "provided": baseline is not None,
            "report_sha256": baseline_report_sha,
            "comparison_scope": comparison_scope,
            "new_count": new_count,
            "existing_count": existing_count,
            "resolved_count": resolved_count,
        },
        "summary": {
            "candidate_count": len(findings),
            "new_candidate_count": new_count,
            "existing_candidate_count": existing_count,
            "high_confidence_candidate_count": sum(
                float(item["static_confidence"]) >= 0.9 for item in findings
            ),
            "redaction_count": sum(int(item["redaction_count"]) for item in findings),
        },
        "policy": policy,
        "findings": findings,
    }
    report["report_sha256"] = _sha256_bytes(_canonical_bytes(report))
    return report


def verify_report_sha256(report: dict[str, Any]) -> bool:
    expected = report.get("report_sha256")
    if not isinstance(expected, str):
        return False
    payload = dict(report)
    payload.pop("report_sha256", None)
    return _sha256_bytes(_canonical_bytes(payload)) == expected
