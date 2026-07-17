import traceback
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.ingestion import prepare_source
from app.services.static_analysis import analyze_repository

settings = get_settings()


async def process_scan(scan_id: str) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.error = None
        await session.commit()

    try:
        async with SessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            assert scan is not None
            workspace = Path(scan.workspace_path)
            prepared = await prepare_source(
                workspace=workspace,
                source_type=scan.source_type,
                source_url=scan.source_url,
                archive_path=workspace / "source.zip" if scan.source_type == "zip" else None,
                settings=settings,
            )
            candidates = analyze_repository(prepared.repository, prepared.structure)
            await session.execute(delete(Finding).where(Finding.scan_id == scan_id))
            session.add_all(
                [
                    Finding(
                        scan_id=scan_id,
                        rule_id=item.rule_id,
                        title=item.title,
                        file_path=item.file_path,
                        line=item.line,
                        end_line=item.end_line,
                        language=item.language,
                        snippet=item.snippet,
                        static_rationale=item.rationale,
                        static_confidence=item.confidence,
                        llm_status="pending",
                    )
                    for item in candidates
                ]
            )
            scan.structure = prepared.structure
            scan.file_count = len(prepared.structure)
            scan.candidate_count = len(candidates)
            scan.status = "completed"
            scan.completed_at = datetime.now(UTC)
            await session.commit()
    except Exception as exc:
        async with SessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}"[:4000]
                scan.completed_at = datetime.now(UTC)
                await session.commit()
