import shutil
from pathlib import Path

from app.core.config import Settings
from app.models.scan import Scan


class RescanError(ValueError):
    pass


def prepare_rescan(baseline: Scan, scan_id: str, settings: Settings) -> Scan:
    workspace = settings.scans_dir / scan_id
    workspace.mkdir(parents=True, exist_ok=False)
    if baseline.source_type == "zip":
        scans_root = settings.scans_dir.resolve()
        baseline_workspace = Path(baseline.workspace_path).resolve()
        source_archive = (baseline_workspace / "source.zip").resolve()
        if (
            not baseline_workspace.is_relative_to(scans_root)
            or not source_archive.is_relative_to(baseline_workspace)
            or not source_archive.is_file()
        ):
            workspace.rmdir()
            raise RescanError("Baseline ZIP source is no longer available")
        shutil.copy2(source_archive, workspace / "source.zip")
        return Scan(
            id=scan_id,
            status="queued",
            source_type="zip",
            original_filename=baseline.original_filename,
            workspace_path=str(workspace),
        )
    if baseline.source_type == "git" and baseline.source_url:
        return Scan(
            id=scan_id,
            status="queued",
            source_type="git",
            source_url=baseline.source_url,
            workspace_path=str(workspace),
        )
    workspace.rmdir()
    raise RescanError("Baseline source cannot be rescanned")
