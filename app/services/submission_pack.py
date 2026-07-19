from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import zipfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.version import APP_VERSION

SUBMISSION_PACK_SCHEMA_VERSION = "sentinel-submission-pack-v1"
DEFAULT_REPOSITORY_URL = "https://github.com/DizzyZ7/Sentinel"
DEFAULT_GHCR_IMAGE = "ghcr.io/dizzyz7/sentinel:latest"
DEFAULT_TRACK = "Developer Tools"
DEFAULT_TAGLINE = "Evidence-to-patch security review that makes AI prove a fix before a human can approve it."

REQUIRED_DOCUMENTS = (
    "README.md",
    "LICENSE",
    "docs/DEVPOST_SUBMISSION.md",
    "docs/VIDEO_SCRIPT.md",
    "docs/RECORDING_GUIDE.md",
    "docs/SUBMISSION_CHECKLIST.md",
    "docs/SUBMISSION_HANDOFF.md",
    "docs/JUDGE_GUIDE.md",
    "docs/BUILD_LOG.md",
    "docs/EVALUATION.md",
    "docs/LOCAL_CLI.md",
)


@dataclass(frozen=True, slots=True)
class PackFile:
    path: str
    role: str
    size_bytes: int
    sha256: str


class SubmissionPackError(ValueError):
    pass


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def verify_manifest_sha256(manifest: dict[str, Any]) -> bool:
    expected = manifest.get("manifest_sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    payload = dict(manifest)
    payload.pop("manifest_sha256", None)
    return _sha256_bytes(_canonical_bytes(payload)) == expected


def _normalized_timestamp(source_date_epoch: int | None) -> datetime:
    epoch = source_date_epoch
    if epoch is None:
        raw = os.getenv("SOURCE_DATE_EPOCH", "").strip()
        epoch = int(raw) if raw else 315532800
    return datetime.fromtimestamp(max(epoch, 315532800), tz=UTC).replace(microsecond=0)


def _zip_datetime(value: datetime) -> tuple[int, int, int, int, int, int]:
    utc = value.astimezone(UTC)
    year = min(max(utc.year, 1980), 2107)
    return year, utc.month, utc.day, utc.hour, utc.minute, utc.second - utc.second % 2


def _copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _pack_file(path: Path, root: Path, role: str) -> PackFile:
    return PackFile(
        path=path.relative_to(root).as_posix(),
        role=role,
        size_bytes=path.stat().st_size,
        sha256=_sha256_file(path),
    )


def _safe_external_name(path: Path, used: set[str]) -> str:
    candidate = path.name
    stem = path.stem
    suffix = path.suffix
    index = 2
    while candidate in used:
        candidate = f"{stem}-{index}{suffix}"
        index += 1
    used.add(candidate)
    return candidate


def _submission_copy(
    *,
    repository_url: str,
    ghcr_image: str,
    video_url: str,
    codex_session_id: str,
    devpost_url: str,
) -> str:
    video = video_url or "ADD PUBLIC YOUTUBE URL"
    session = codex_session_id or "ADD PRIMARY /feedback CODEX SESSION ID"
    devpost = devpost_url or "ADD DEVPOST SUBMISSION URL AFTER SAVING THE PROJECT"
    return f"""# Sentinel — Devpost copy sheet

## Project name

Sentinel

## Tagline

{DEFAULT_TAGLINE}

## Track

{DEFAULT_TRACK}

## Repository

{repository_url}

## Demo video

{video}

## Demo / testing path

```bash
docker compose -f compose.demo.yml up -d
```

Then open `http://localhost:8000` and run **Run the 60-second security demo**.

## Prebuilt image

`{ghcr_image}`

## Primary Codex Session ID

`{session}`

## Devpost project URL

{devpost}

## One-line summary

Sentinel combines deterministic security evidence, GPT-5.6 contextual review, and constrained patch generation.
It adds non-executing regression proof and explicit human approval in one local-first workflow.

## Required disclosure

The deterministic validation results are committed fixture results, not a claim of general-world accuracy.
The replay path is explicitly labelled and separate from the live GPT-5.6 path.
"""


def build_submission_pack(
    *,
    root: Path,
    output_dir: Path,
    evidence_paths: Iterable[Path] = (),
    repository_url: str = DEFAULT_REPOSITORY_URL,
    ghcr_image: str = DEFAULT_GHCR_IMAGE,
    video_url: str = "",
    codex_session_id: str = "",
    devpost_url: str = "",
    ghcr_public_confirmed: bool = False,
    devpost_complete_confirmed: bool = False,
    source_date_epoch: int | None = None,
    strict: bool = False,
    archive_path: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    output_dir = output_dir.resolve()
    timestamp = _normalized_timestamp(source_date_epoch)

    missing_documents = [item for item in REQUIRED_DOCUMENTS if not (root / item).is_file()]
    if missing_documents:
        raise SubmissionPackError(f"Missing required submission documents: {missing_documents}")

    external_fields = {
        "video_url": video_url.strip(),
        "codex_session_id": codex_session_id.strip(),
        "ghcr_public_confirmed": bool(ghcr_public_confirmed),
        "devpost_complete_confirmed": bool(devpost_complete_confirmed),
    }
    missing_manual_fields = [
        key
        for key, value in external_fields.items()
        if value is False or (isinstance(value, str) and not value)
    ]
    if strict and missing_manual_fields:
        raise SubmissionPackError(
            "Submission pack is not final; missing manual fields: " + ", ".join(missing_manual_fields)
        )

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    documents_root = output_dir / "documents"
    evidence_root = output_dir / "evidence"
    metadata_root = output_dir / "metadata"
    metadata_root.mkdir(parents=True)

    files: list[PackFile] = []
    for relative in REQUIRED_DOCUMENTS:
        source = root / relative
        destination = documents_root / relative
        _copy_file(source, destination)
        files.append(_pack_file(destination, output_dir, "document"))

    copy_sheet = documents_root / "DEVPOST_COPY.md"
    copy_sheet.write_text(
        _submission_copy(
            repository_url=repository_url,
            ghcr_image=ghcr_image,
            video_url=video_url.strip(),
            codex_session_id=codex_session_id.strip(),
            devpost_url=devpost_url.strip(),
        ),
        encoding="utf-8",
    )
    files.append(_pack_file(copy_sheet, output_dir, "copy_sheet"))

    used_names: set[str] = set()
    for evidence_path in evidence_paths:
        source = evidence_path.resolve()
        if not source.is_file():
            raise SubmissionPackError(f"Evidence file does not exist: {evidence_path}")
        name = _safe_external_name(source, used_names)
        destination = evidence_root / name
        _copy_file(source, destination)
        files.append(_pack_file(destination, output_dir, "evidence"))

    files.sort(key=lambda item: item.path)
    manifest: dict[str, Any] = {
        "schema_version": SUBMISSION_PACK_SCHEMA_VERSION,
        "app_version": APP_VERSION,
        "generated_at": timestamp.isoformat().replace("+00:00", "Z"),
        "project": {
            "name": "Sentinel",
            "tagline": DEFAULT_TAGLINE,
            "track": DEFAULT_TRACK,
            "repository_url": repository_url,
            "ghcr_image": ghcr_image,
            "demo_command": "docker compose -f compose.demo.yml up -d",
        },
        "submission": {
            "video_url": video_url.strip() or None,
            "codex_session_id": codex_session_id.strip() or None,
            "devpost_url": devpost_url.strip() or None,
            "ghcr_public_confirmed": bool(ghcr_public_confirmed),
            "devpost_complete_confirmed": bool(devpost_complete_confirmed),
            "missing_manual_fields": missing_manual_fields,
            "ready_for_submission": not missing_manual_fields,
        },
        "safety": {
            "source_executed": False,
            "dependencies_installed_from_scanned_repository": False,
            "patches_auto_applied": False,
            "secrets_exported": False,
        },
        "files": [asdict(item) for item in files],
    }
    manifest["manifest_sha256"] = _sha256_bytes(_canonical_bytes(manifest))

    manifest_path = metadata_root / "SUBMISSION_MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    checksum_lines = [f"{item.sha256}  {item.path}" for item in files]
    checksum_lines.append(f"{_sha256_file(manifest_path)}  metadata/SUBMISSION_MANIFEST.json")
    checksums_path = output_dir / "SHA256SUMS"
    checksums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    if archive_path is not None:
        archive_path = archive_path.resolve()
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        if archive_path.exists():
            archive_path.unlink()
        zip_time = _zip_datetime(timestamp)
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(output_dir.rglob("*")):
                if not path.is_file():
                    continue
                relative = path.relative_to(output_dir).as_posix()
                info = zipfile.ZipInfo(relative, date_time=zip_time)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    return manifest
