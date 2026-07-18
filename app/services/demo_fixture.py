from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

DEMO_SOURCE = Path("demo/judge-demo")


def create_judge_demo_archive(destination: Path) -> Path:
    if not DEMO_SOURCE.is_dir():
        raise FileNotFoundError("Built-in demo source is unavailable")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, "w", ZIP_DEFLATED) as archive:
        for path in sorted(DEMO_SOURCE.rglob("*")):
            if path.is_file():
                archive.write(path, Path("judge-demo") / path.relative_to(DEMO_SOURCE))
    return destination
