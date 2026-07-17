import asyncio
import os
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import aiofiles
from fastapi import UploadFile

from app.core.config import Settings

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}
IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".next",
}


@dataclass(slots=True)
class PreparedSource:
    workspace: Path
    repository: Path
    structure: list[dict]


class IngestionError(ValueError):
    pass


async def save_upload(upload: UploadFile, destination: Path, max_bytes: int) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    async with aiofiles.open(destination, "wb") as target:
        while chunk := await upload.read(1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                await target.close()
                destination.unlink(missing_ok=True)
                raise IngestionError(f"Archive exceeds {max_bytes} bytes")
            await target.write(chunk)
    return total


def validate_git_url(url: str, allowed_hosts: list[str]) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise IngestionError("Only http(s) Git URLs are allowed")
    hostname = (parsed.hostname or "").lower()
    if hostname not in allowed_hosts:
        raise IngestionError(f"Git host '{hostname}' is not allowed")
    if parsed.username or parsed.password:
        raise IngestionError("Credentials in Git URL are not allowed")
    return url.strip()


async def clone_repository(url: str, destination: Path, settings: Settings) -> None:
    validated = validate_git_url(url, settings.allowed_git_hosts)
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ASKPASS": "/bin/false",
    }
    process = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        validated,
        str(destination),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    _, stderr = await asyncio.wait_for(process.communicate(), timeout=90)
    if process.returncode != 0:
        raise IngestionError(f"git clone failed: {stderr.decode(errors='replace')[-800:]}")


def _safe_destination(root: Path, member_name: str) -> Path:
    candidate = (root / member_name).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise IngestionError(f"Unsafe ZIP path: {member_name}")
    return candidate


def extract_zip(archive: Path, destination: Path, settings: Settings) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    extracted = 0
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > settings.max_archive_files:
            raise IngestionError("Archive contains too many files")
        for member in members:
            if member.is_dir():
                continue
            if member.file_size < 0:
                raise IngestionError("Archive contains invalid file size")
            extracted += member.file_size
            if extracted > settings.max_extracted_bytes:
                raise IngestionError("Archive expands beyond configured limit")
            target = _safe_destination(destination, member.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open(member) as reader, target.open("wb") as writer:
                shutil.copyfileobj(reader, writer)


def normalize_repository_root(destination: Path) -> Path:
    children = [item for item in destination.iterdir() if item.name not in {"__MACOSX", ".DS_Store"}]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return destination


def ensure_git_baseline(repository: Path) -> None:
    if (repository / ".git").exists():
        return
    commands = [
        ["git", "init", "-q"],
        ["git", "add", "-A"],
        [
            "git",
            "-c",
            "user.name=Sentinel",
            "-c",
            "user.email=sentinel@local",
            "commit",
            "-qm",
            "Sentinel scan baseline",
        ],
    ]
    for command in commands:
        result = subprocess.run(command, cwd=repository, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise IngestionError(f"Could not prepare Git baseline: {result.stderr[-500:]}")


def build_structure(repository: Path, settings: Settings) -> list[dict]:
    structure: list[dict] = []
    for path in repository.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(repository)
        if any(part in IGNORED_DIRS for part in relative.parts):
            continue
        language = SUPPORTED_EXTENSIONS.get(path.suffix.lower())
        if not language:
            continue
        size = path.stat().st_size
        if size > settings.max_source_file_bytes:
            continue
        structure.append({"path": relative.as_posix(), "language": language, "size": size})
    return sorted(structure, key=lambda item: item["path"])


async def prepare_source(
    workspace: Path,
    source_type: str,
    settings: Settings,
    source_url: str | None = None,
    archive_path: Path | None = None,
) -> PreparedSource:
    repository = workspace / "repo"
    if repository.exists():
        shutil.rmtree(repository)

    if source_type == "git":
        if not source_url:
            raise IngestionError("Missing Git URL")
        await clone_repository(source_url, repository, settings)
    elif source_type == "zip":
        if not archive_path or not archive_path.exists():
            raise IngestionError("Missing ZIP archive")
        extract_root = workspace / "extracted"
        if extract_root.exists():
            shutil.rmtree(extract_root)
        extract_zip(archive_path, extract_root, settings)
        normalized = normalize_repository_root(extract_root)
        shutil.move(str(normalized), str(repository))
    else:
        raise IngestionError(f"Unsupported source type: {source_type}")

    ensure_git_baseline(repository)
    structure = build_structure(repository, settings)
    if not structure:
        raise IngestionError("No supported Python or JavaScript/TypeScript files found")
    return PreparedSource(workspace=workspace, repository=repository, structure=structure)
