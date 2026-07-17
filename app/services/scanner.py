from datetime import UTC, datetime
from pathlib import Path

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.scan import Scan
from app.services.ingestion import prepare_source

settings = get_settings()


async def process_scan(scan_id: str) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        await session.commit()
        try:
            workspace = Path(scan.workspace_path)
            prepared = await prepare_source(
                workspace=workspace,
                source_type=scan.source_type,
                source_url=scan.source_url,
                archive_path=workspace / "source.zip" if scan.source_type == "zip" else None,
                settings=settings,
            )
            scan.structure = prepared.structure
            scan.file_count = len(prepared.structure)
            scan.status = "completed"
            scan.completed_at = datetime.now(UTC)
        except Exception as exc:
            scan.status = "failed"
            scan.error = f"{type(exc).__name__}: {exc}"[:2000]
            scan.completed_at = datetime.now(UTC)
        await session.commit()
