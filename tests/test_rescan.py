from pathlib import Path

import pytest

from app.core.config import Settings
from app.models.scan import Scan
from app.services.rescan import RescanError, prepare_rescan


def test_prepare_zip_rescan_copies_original_archive(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data", database_url=f"sqlite+aiosqlite:///{tmp_path}/test.db")
    baseline_workspace = settings.scans_dir / "baseline"
    baseline_workspace.mkdir(parents=True)
    source = baseline_workspace / "source.zip"
    source.write_bytes(b"sentinel-archive")
    baseline = Scan(
        id="baseline",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(baseline_workspace),
    )

    rescan = prepare_rescan(baseline, "current", settings)

    assert rescan.source_type == "zip"
    assert rescan.original_filename == "repo.zip"
    assert Path(rescan.workspace_path, "source.zip").read_bytes() == b"sentinel-archive"


def test_prepare_git_rescan_reuses_validated_source_url(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data", database_url=f"sqlite+aiosqlite:///{tmp_path}/test.db")
    baseline = Scan(
        id="baseline",
        status="completed",
        source_type="git",
        source_url="https://github.com/example/project.git",
        workspace_path=str(settings.scans_dir / "baseline"),
    )

    rescan = prepare_rescan(baseline, "current", settings)

    assert rescan.source_type == "git"
    assert rescan.source_url == baseline.source_url
    assert Path(rescan.workspace_path).is_dir()


def test_prepare_zip_rescan_fails_when_archive_was_removed(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data", database_url=f"sqlite+aiosqlite:///{tmp_path}/test.db")
    baseline_workspace = settings.scans_dir / "baseline"
    baseline_workspace.mkdir(parents=True)
    baseline = Scan(
        id="baseline",
        status="completed",
        source_type="zip",
        original_filename="repo.zip",
        workspace_path=str(baseline_workspace),
    )

    with pytest.raises(RescanError, match="no longer available"):
        prepare_rescan(baseline, "current", settings)
    assert not (settings.scans_dir / "current").exists()
