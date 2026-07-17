from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
ARCHIVES = DEMO / "archives"
ARCHIVES.mkdir(exist_ok=True)

for source in ("python-vulnerable", "node-vulnerable", "mixed-vulnerable"):
    source_dir = DEMO / source
    archive_path = ARCHIVES / f"{source}.zip"
    with ZipFile(archive_path, "w", ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                archive.write(path, Path(source) / path.relative_to(source_dir))
    print(archive_path)
