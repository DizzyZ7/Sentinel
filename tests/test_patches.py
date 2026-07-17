from pathlib import Path

import pytest

from app.services.patches import validate_and_store_patch


@pytest.mark.asyncio
async def test_patch_validation_accepts_small_valid_python_patch(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    diff = """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = 2
"""
    result = await validate_and_store_patch(repository, tmp_path / "patches", "finding", "app.py", diff)
    assert result.valid is True


@pytest.mark.asyncio
async def test_patch_validation_rejects_other_paths(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    diff = """--- a/other.py
+++ b/other.py
@@ -1 +1 @@
-value = 1
+value = 2
"""
    result = await validate_and_store_patch(repository, tmp_path / "patches", "finding", "app.py", diff)
    assert result.valid is False
    assert "reviewed file" in (result.error or "")


@pytest.mark.asyncio
async def test_patch_validation_rejects_invalid_python(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    diff = """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = 1
+value = (
"""
    result = await validate_and_store_patch(repository, tmp_path / "patches", "finding", "app.py", diff)
    assert result.valid is False
    assert "syntactically valid" in (result.error or "")
