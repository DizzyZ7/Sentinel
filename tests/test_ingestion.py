from pathlib import Path
from zipfile import ZipFile

import pytest

from app.core.config import Settings
from app.services.ingestion import IngestionError, extract_zip, validate_git_url


def test_rejects_zip_slip(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    with ZipFile(archive, "w") as source:
        source.writestr("../escape.py", "print('bad')")
    with pytest.raises(IngestionError):
        extract_zip(archive, tmp_path / "out", Settings())


def test_git_host_allowlist() -> None:
    assert validate_git_url("https://github.com/openai/example.git", ["github.com"])
    with pytest.raises(IngestionError):
        validate_git_url("file:///etc/passwd", ["github.com"])
    with pytest.raises(IngestionError):
        validate_git_url("https://127.0.0.1/repo.git", ["github.com"])
