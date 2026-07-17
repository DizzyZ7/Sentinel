import asyncio
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class PatchValidation:
    valid: bool
    path: Path | None
    error: str | None


DIFF_PATH_RE = re.compile(r"^(?:---|\+\+\+)\s+([ab]/[^\t\n]+)", re.MULTILINE)


def _validate_paths(diff: str, expected_file: str) -> None:
    paths = [match.group(1) for match in DIFF_PATH_RE.finditer(diff)]
    if not paths:
        raise ValueError("Diff does not contain ---/+++ file headers")
    allowed = {f"a/{expected_file}", f"b/{expected_file}"}
    if any(path not in allowed for path in paths):
        raise ValueError("Diff attempts to modify a file outside the reviewed candidate")
    if "../" in diff or "\x00" in diff:
        raise ValueError("Diff contains an unsafe path or null byte")


async def validate_and_store_patch(
    repository: Path,
    patches_dir: Path,
    finding_id: str,
    expected_file: str,
    diff: str,
) -> PatchValidation:
    if not diff.strip():
        return PatchValidation(valid=False, path=None, error="Model returned an empty diff")
    try:
        _validate_paths(diff, expected_file)
    except ValueError as exc:
        return PatchValidation(valid=False, path=None, error=str(exc))

    patches_dir.mkdir(parents=True, exist_ok=True)
    patch_path = patches_dir / f"{finding_id}.patch"
    patch_path.write_text(diff, encoding="utf-8")
    process = await asyncio.create_subprocess_exec(
        "git",
        "apply",
        "--check",
        "--whitespace=nowarn",
        str(patch_path),
        cwd=repository,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode != 0:
        return PatchValidation(
            valid=False,
            path=patch_path,
            error=stderr.decode(errors="replace")[-1200:] or "git apply --check failed",
        )
    return PatchValidation(valid=True, path=patch_path, error=None)
