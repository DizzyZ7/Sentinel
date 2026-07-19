from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.submission_pack import SubmissionPackError, build_submission_pack, verify_manifest_sha256

ROOT = Path(__file__).resolve().parents[1]


def test_submission_pack_builds_hash_covered_draft(tmp_path: Path) -> None:
    evidence = tmp_path / "judge.json"
    evidence.write_text('{"status":"passed"}\n', encoding="utf-8")
    output = tmp_path / "pack"
    archive = tmp_path / "pack.zip"

    manifest = build_submission_pack(
        root=ROOT,
        output_dir=output,
        evidence_paths=[evidence],
        archive_path=archive,
        source_date_epoch=1_720_000_000,
    )

    assert manifest["schema_version"] == "sentinel-submission-pack-v1"
    assert manifest["submission"]["ready_for_submission"] is False
    assert set(manifest["submission"]["missing_manual_fields"]) == {
        "video_url",
        "codex_session_id",
        "ghcr_public_confirmed",
        "devpost_complete_confirmed",
    }
    stored = json.loads((output / "metadata/SUBMISSION_MANIFEST.json").read_text(encoding="utf-8"))
    assert verify_manifest_sha256(stored)
    assert archive.is_file()
    assert archive.stat().st_size > 0
    assert (output / "documents/DEVPOST_COPY.md").is_file()
    assert (output / "evidence/judge.json").read_text(encoding="utf-8") == '{"status":"passed"}\n'


def test_submission_pack_strict_requires_all_manual_fields(tmp_path: Path) -> None:
    with pytest.raises(SubmissionPackError, match="video_url"):
        build_submission_pack(root=ROOT, output_dir=tmp_path / "pack", strict=True)


def test_submission_pack_strict_final_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_zip = tmp_path / "first.zip"
    second_zip = tmp_path / "second.zip"
    kwargs = {
        "root": ROOT,
        "video_url": "https://youtu.be/sentinel-demo",
        "codex_session_id": "session-sentinel-primary",
        "devpost_url": "https://devpost.com/software/sentinel",
        "ghcr_public_confirmed": True,
        "devpost_complete_confirmed": True,
        "source_date_epoch": 1_720_000_000,
        "strict": True,
    }

    first_manifest = build_submission_pack(output_dir=first, archive_path=first_zip, **kwargs)
    second_manifest = build_submission_pack(output_dir=second, archive_path=second_zip, **kwargs)

    assert first_manifest["submission"]["ready_for_submission"] is True
    assert first_manifest["manifest_sha256"] == second_manifest["manifest_sha256"]
    assert first_zip.read_bytes() == second_zip.read_bytes()
    copy_sheet = (first / "documents/DEVPOST_COPY.md").read_text(encoding="utf-8")
    assert "ADD PUBLIC" not in copy_sheet
    assert "session-sentinel-primary" in copy_sheet
