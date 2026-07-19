from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from app.services.submission_pack import SubmissionPackError, build_submission_pack

ROOT = Path(__file__).resolve().parents[1]


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "done", "public"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a hash-covered Sentinel competition submission pack.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--evidence", action="append", type=Path, default=[])
    parser.add_argument("--repository-url", default="https://github.com/DizzyZ7/Sentinel")
    parser.add_argument("--ghcr-image", default="ghcr.io/dizzyz7/sentinel:latest")
    parser.add_argument("--video-url", default=os.getenv("SENTINEL_VIDEO_URL", ""))
    parser.add_argument("--codex-session-id", default=os.getenv("SENTINEL_CODEX_SESSION_ID", ""))
    parser.add_argument("--devpost-url", default=os.getenv("SENTINEL_DEVPOST_URL", ""))
    parser.add_argument(
        "--ghcr-public",
        action="store_true",
        default=_truthy(os.getenv("SENTINEL_GHCR_PUBLIC", "")),
    )
    parser.add_argument(
        "--devpost-complete",
        action="store_true",
        default=_truthy(os.getenv("SENTINEL_DEVPOST_COMPLETE", "")),
    )
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    try:
        manifest = build_submission_pack(
            root=args.root,
            output_dir=args.output_dir,
            archive_path=args.archive,
            evidence_paths=args.evidence,
            repository_url=args.repository_url,
            ghcr_image=args.ghcr_image,
            video_url=args.video_url,
            codex_session_id=args.codex_session_id,
            devpost_url=args.devpost_url,
            ghcr_public_confirmed=args.ghcr_public,
            devpost_complete_confirmed=args.devpost_complete,
            source_date_epoch=args.source_date_epoch,
            strict=args.strict,
        )
    except SubmissionPackError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2))
        return 2

    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
