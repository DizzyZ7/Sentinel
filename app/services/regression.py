import asyncio
import hashlib
import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from app.models.finding import Finding
from app.services.static_analysis import Candidate, analyze_repository

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)
CheckStatus = Literal["passed", "failed", "inconclusive"]
VerificationStatus = Literal["passed", "failed", "inconclusive", "skipped"]


@dataclass(slots=True)
class RegressionResult:
    status: VerificationStatus
    mode: str
    verifier_version: str
    before_detected: bool | None
    after_detected: bool | None
    patch_applied: bool
    source_executed: bool
    before_digest: str | None
    after_digest: str | None
    checks: list[dict]
    artifact_path: Path | None
    error: str | None


@dataclass(frozen=True, slots=True)
class ChangedRange:
    start: int
    end: int


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ranges(diff: str) -> tuple[list[ChangedRange], list[ChangedRange]]:
    old_ranges: list[ChangedRange] = []
    new_ranges: list[ChangedRange] = []
    for match in HUNK_RE.finditer(diff):
        old_start = int(match.group(1))
        old_length = int(match.group(2) or "1")
        new_start = int(match.group(3))
        new_length = int(match.group(4) or "1")
        old_ranges.append(ChangedRange(old_start, old_start + max(old_length, 1) - 1))
        new_ranges.append(ChangedRange(new_start, new_start + max(new_length, 1) - 1))
    return old_ranges, new_ranges


def _overlaps(candidate: Candidate, ranges: list[ChangedRange], margin: int = 1) -> bool:
    return any(
        candidate.end_line >= item.start - margin and candidate.line <= item.end + margin
        for item in ranges
    )


def _candidate_lines(
    repository: Path,
    finding: Finding,
    ranges: list[ChangedRange],
) -> list[int]:
    source = repository / finding.file_path
    if not source.is_file():
        return []
    structure = [
        {
            "path": finding.file_path,
            "language": finding.language,
            "size": source.stat().st_size,
        }
    ]
    candidates = analyze_repository(repository, structure)
    return [
        candidate.line
        for candidate in candidates
        if candidate.rule_id == finding.rule_id
        and candidate.file_path == finding.file_path
        and _overlaps(candidate, ranges)
    ]


async def _apply_patch(root: Path, patch_path: Path) -> tuple[bool, str | None]:
    process = await asyncio.create_subprocess_exec(
        "git",
        "apply",
        "--whitespace=nowarn",
        str(patch_path),
        cwd=root,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode == 0:
        return True, None
    return False, stderr.decode(errors="replace")[-1200:] or "git apply failed"


def _check(name: str, status: CheckStatus, detail: str) -> dict:
    return {"name": name, "status": status, "detail": detail}


async def verify_patch_regression(
    repository: Path,
    workspace: Path,
    finding: Finding,
    patch_path: Path,
) -> RegressionResult:
    mode = "non_executing_static_regression"
    version = "0.4.0"
    checks: list[dict] = [
        _check(
            "source_execution",
            "passed",
            "Repository code was never imported, executed, or used to install dependencies.",
        )
    ]
    source = repository / finding.file_path
    if not source.is_file():
        return RegressionResult(
            status="inconclusive",
            mode=mode,
            verifier_version=version,
            before_detected=None,
            after_detected=None,
            patch_applied=False,
            source_executed=False,
            before_digest=None,
            after_digest=None,
            checks=checks + [_check("source_file", "inconclusive", "Reviewed source file is unavailable.")],
            artifact_path=None,
            error="Reviewed source file is unavailable",
        )

    diff = patch_path.read_text(encoding="utf-8")
    old_ranges, new_ranges = _ranges(diff)
    touches_finding = any(
        finding.end_line >= item.start - 1 and finding.line <= item.end + 1 for item in old_ranges
    )
    checks.append(
        _check(
            "patch_scope",
            "passed" if touches_finding else "inconclusive",
            (
                "Patch hunk overlaps the original finding."
                if touches_finding
                else "Patch hunk is not near the original finding."
            ),
        )
    )

    before_digest = _digest(source)
    before_lines = _candidate_lines(repository, finding, old_ranges or [ChangedRange(finding.line, finding.end_line)])
    before_detected = bool(before_lines)
    checks.append(
        _check(
            "before_reproduction",
            "passed" if before_detected else "inconclusive",
            f"Original deterministic candidate reproduced at line(s): {before_lines}."
            if before_detected
            else "The current analyzer could not reproduce the original candidate near the patch.",
        )
    )

    with tempfile.TemporaryDirectory(prefix="sentinel-regression-") as temporary:
        root = Path(temporary)
        patched_source = root / finding.file_path
        patched_source.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, patched_source)
        applied, apply_error = await _apply_patch(root, patch_path)
        checks.append(
            _check(
                "virtual_patch_application",
                "passed" if applied else "failed",
                "Patch applied to an isolated one-file copy."
                if applied
                else f"Patch could not be applied to the isolated copy: {apply_error}",
            )
        )
        if not applied:
            return RegressionResult(
                status="failed",
                mode=mode,
                verifier_version=version,
                before_detected=before_detected,
                after_detected=None,
                patch_applied=False,
                source_executed=False,
                before_digest=before_digest,
                after_digest=None,
                checks=checks,
                artifact_path=None,
                error=apply_error,
            )

        after_digest = _digest(patched_source)
        changed = before_digest != after_digest
        checks.append(
            _check(
                "source_change",
                "passed" if changed else "failed",
                "The patched file digest differs from the original."
                if changed
                else "The patch did not change the reviewed file digest.",
            )
        )
        after_lines = _candidate_lines(root, finding, new_ranges or [ChangedRange(finding.line, finding.end_line)])
        after_detected = bool(after_lines)
        checks.append(
            _check(
                "after_regression_scan",
                "failed" if after_detected else "passed",
                f"The same source-to-sink candidate remains at line(s): {after_lines}."
                if after_detected
                else "The same deterministic source-to-sink candidate is absent near the patched hunk.",
            )
        )

    if not changed or after_detected:
        status: VerificationStatus = "failed"
        error = "Regression proof failed: the patch did not remove the deterministic attack path."
    elif not touches_finding or not before_detected:
        status = "inconclusive"
        error = "Regression proof is inconclusive because the original path could not be fully reproduced."
    else:
        status = "passed"
        error = None

    artifact_dir = workspace / "verifications"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{finding.id}.json"
    artifact = {
        "finding_id": finding.id,
        "rule_id": finding.rule_id,
        "file_path": finding.file_path,
        "status": status,
        "mode": mode,
        "verifier_version": version,
        "source_executed": False,
        "before_digest": before_digest,
        "after_digest": after_digest,
        "before_candidate_lines": before_lines,
        "after_candidate_lines": after_lines,
        "checks": checks,
        "verified_at": datetime.now(UTC).isoformat(),
    }
    artifact_path.write_text(json.dumps(artifact, indent=2, ensure_ascii=False), encoding="utf-8")
    return RegressionResult(
        status=status,
        mode=mode,
        verifier_version=version,
        before_detected=before_detected,
        after_detected=after_detected,
        patch_applied=True,
        source_executed=False,
        before_digest=before_digest,
        after_digest=after_digest,
        checks=checks,
        artifact_path=artifact_path,
        error=error,
    )
