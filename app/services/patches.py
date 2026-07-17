import ast
import asyncio
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class PatchValidation:
    valid: bool
    path: Path | None
    error: str | None


DIFF_PATH_RE = re.compile(r"^(?:---|\+\+\+)\s+([ab]/[^\t\n]+)", re.MULTILINE)
FORBIDDEN_DIFF_MARKERS = (
    "GIT binary patch",
    "Binary files ",
    "new file mode ",
    "deleted file mode ",
    "old mode ",
    "new mode ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
)


def _changed_line_count(diff: str) -> int:
    return sum(
        1
        for line in diff.splitlines()
        if (line.startswith("+") and not line.startswith("+++"))
        or (line.startswith("-") and not line.startswith("---"))
    )


def _validate_diff_shape(diff: str, expected_file: str, max_bytes: int, max_changed_lines: int) -> None:
    if len(diff.encode("utf-8")) > max_bytes:
        raise ValueError(f"Diff exceeds the {max_bytes}-byte safety limit")
    if any(marker in diff for marker in FORBIDDEN_DIFF_MARKERS):
        raise ValueError("Diff contains a binary, file lifecycle, rename, copy, or mode change")
    if "../" in diff or "\x00" in diff:
        raise ValueError("Diff contains an unsafe path or null byte")

    paths = [match.group(1) for match in DIFF_PATH_RE.finditer(diff)]
    expected_paths = [f"a/{expected_file}", f"b/{expected_file}"]
    if paths != expected_paths:
        raise ValueError("Diff must modify exactly the reviewed file with canonical a/ and b/ headers")

    changed_lines = _changed_line_count(diff)
    if changed_lines == 0:
        raise ValueError("Diff does not change any source lines")
    if changed_lines > max_changed_lines:
        raise ValueError(f"Diff changes {changed_lines} lines; limit is {max_changed_lines}")


async def _run_git_apply(repository: Path, patch_path: Path, check_only: bool) -> tuple[int, str]:
    command = ["git", "apply"]
    if check_only:
        command.append("--check")
    command.extend(["--whitespace=nowarn", str(patch_path)])
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=repository,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    return process.returncode, stderr.decode(errors="replace")[-1200:]


async def _validate_python_syntax(repository: Path, patch_path: Path, expected_file: str) -> None:
    if not expected_file.lower().endswith(".py"):
        return
    source_path = repository / expected_file
    with tempfile.TemporaryDirectory(prefix="sentinel-patch-") as temporary:
        root = Path(temporary)
        target = root / expected_file
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target)
        return_code, error = await _run_git_apply(root, patch_path, check_only=False)
        if return_code != 0:
            raise ValueError(error or "Could not materialize patch for syntax validation")
        try:
            ast.parse(target.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeError) as exc:
            raise ValueError(f"Patched Python file is not syntactically valid: {exc}") from exc


async def validate_and_store_patch(
    repository: Path,
    patches_dir: Path,
    finding_id: str,
    expected_file: str,
    diff: str,
    max_bytes: int = 64_000,
    max_changed_lines: int = 200,
) -> PatchValidation:
    if not diff.strip():
        return PatchValidation(valid=False, path=None, error="Model returned an empty diff")
    try:
        _validate_diff_shape(diff, expected_file, max_bytes, max_changed_lines)
    except ValueError as exc:
        return PatchValidation(valid=False, path=None, error=str(exc))

    patches_dir.mkdir(parents=True, exist_ok=True)
    patch_path = patches_dir / f"{finding_id}.patch"
    patch_path.write_text(diff, encoding="utf-8")
    return_code, error = await _run_git_apply(repository, patch_path, check_only=True)
    if return_code != 0:
        return PatchValidation(valid=False, path=patch_path, error=error or "git apply --check failed")
    try:
        await _validate_python_syntax(repository, patch_path, expected_file)
    except ValueError as exc:
        return PatchValidation(valid=False, path=patch_path, error=str(exc))
    return PatchValidation(valid=True, path=patch_path, error=None)
