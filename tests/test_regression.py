from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.regression import verify_patch_regression


def finding() -> SimpleNamespace:
    return SimpleNamespace(
        id="finding-1",
        rule_id="PY_SQL_INTERPOLATION",
        file_path="app.py",
        line=3,
        end_line=3,
        language="python",
    )


@pytest.mark.asyncio
async def test_regression_proof_passes_when_candidate_disappears(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "app.py").write_text(
        'def run(db, user):\n    query = f"SELECT * FROM users WHERE name={user}"\n    return db.execute(query)\n',
        encoding="utf-8",
    )
    patch = tmp_path / "fix.patch"
    patch.write_text(
        '''--- a/app.py
+++ b/app.py
@@ -1,3 +1,2 @@
 def run(db, user):
-    query = f"SELECT * FROM users WHERE name={user}"
-    return db.execute(query)
+    return db.execute("SELECT * FROM users WHERE name=:user", {"user": user})
''',
        encoding="utf-8",
    )
    proof = await verify_patch_regression(repository, tmp_path, finding(), patch)
    assert proof.status == "passed"
    assert proof.before_detected is True
    assert proof.after_detected is False
    assert proof.source_executed is False
    assert proof.artifact_path and proof.artifact_path.is_file()


@pytest.mark.asyncio
async def test_regression_proof_fails_when_candidate_remains(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "app.py").write_text(
        'def run(db, user):\n    query = f"SELECT * FROM users WHERE name={user}"\n    return db.execute(query)\n',
        encoding="utf-8",
    )
    patch = tmp_path / "weak.patch"
    patch.write_text(
        '''--- a/app.py
+++ b/app.py
@@ -1,3 +1,3 @@
 def run(db, user):
-    query = f"SELECT * FROM users WHERE name={user}"
+    query = f"SELECT * FROM users WHERE name = {user}"
     return db.execute(query)
''',
        encoding="utf-8",
    )
    proof = await verify_patch_regression(repository, tmp_path, finding(), patch)
    assert proof.status == "failed"
    assert proof.after_detected is True


@pytest.mark.asyncio
async def test_regression_proof_is_inconclusive_for_unrelated_hunk(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "app.py").write_text(
        (
            'VERSION = "1"\n\n\ndef run(db, user):\n'
            '    query = f"SELECT * FROM users WHERE name={user}"\n'
            '    return db.execute(query)\n'
        ),
        encoding="utf-8",
    )
    item = finding()
    item.line = 6
    item.end_line = 6
    patch = tmp_path / "unrelated.patch"
    patch.write_text(
        '''--- a/app.py
+++ b/app.py
@@ -1,4 +1,4 @@
-VERSION = "1"
+VERSION = "2"
 
 
 def run(db, user):
''',
        encoding="utf-8",
    )
    proof = await verify_patch_regression(repository, tmp_path, item, patch)
    assert proof.status == "inconclusive"
