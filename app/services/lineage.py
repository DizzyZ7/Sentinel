from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.lineage import ScanLineage
from app.models.scan import Scan
from app.schemas.lineage import LineageNode, LineageResponse


async def ensure_root_lineage(db: AsyncSession, scan: Scan) -> ScanLineage:
    existing = await db.get(ScanLineage, scan.id)
    if existing:
        return existing
    lineage = ScanLineage(
        scan_id=scan.id,
        parent_scan_id=None,
        root_scan_id=scan.id,
        generation=0,
    )
    db.add(lineage)
    await db.flush()
    return lineage


async def link_rescan(db: AsyncSession, baseline: Scan, current: Scan) -> ScanLineage:
    parent = await ensure_root_lineage(db, baseline)
    existing = await db.get(ScanLineage, current.id)
    if existing:
        return existing
    lineage = ScanLineage(
        scan_id=current.id,
        parent_scan_id=baseline.id,
        root_scan_id=parent.root_scan_id,
        generation=parent.generation + 1,
    )
    db.add(lineage)
    await db.flush()
    return lineage


def _source_label(scan: Scan) -> str:
    if scan.source_type == "git":
        return scan.source_url or "Git repository"
    return scan.original_filename or "ZIP repository"


def _created_key(scan: Scan) -> tuple[datetime, str]:
    return scan.created_at, scan.id


async def build_lineage_response(db: AsyncSession, current: Scan) -> LineageResponse:
    current_lineage = await db.get(ScanLineage, current.id)
    if current_lineage:
        root_scan_id = current_lineage.root_scan_id
        parent_scan_id = current_lineage.parent_scan_id
        result = await db.execute(
            select(Scan, ScanLineage)
            .join(ScanLineage, ScanLineage.scan_id == Scan.id)
            .where(ScanLineage.root_scan_id == root_scan_id)
        )
        records = list(result.all())
    else:
        root_scan_id = current.id
        parent_scan_id = None
        records = [(current, None)]

    records.sort(key=lambda pair: (pair[1].generation if pair[1] else 0, *_created_key(pair[0])))
    nodes: list[LineageNode] = []
    candidates: list[Scan] = []
    for scan, lineage in records:
        generation = lineage.generation if lineage else 0
        eligible = (
            scan.id != current.id
            and scan.status in {"completed", "failed"}
            and scan.created_at <= current.created_at
        )
        if eligible:
            candidates.append(scan)
        nodes.append(
            LineageNode(
                scan_id=scan.id,
                parent_scan_id=lineage.parent_scan_id if lineage else None,
                root_scan_id=lineage.root_scan_id if lineage else scan.id,
                generation=generation,
                status=scan.status,
                source_type=scan.source_type,
                source_label=_source_label(scan),
                created_at=scan.created_at,
                completed_at=scan.completed_at,
                risk_score=scan.risk_score,
                finding_count=scan.finding_count,
                candidate_count=scan.candidate_count,
                is_current=scan.id == current.id,
                eligible_baseline=eligible,
            )
        )

    default_baseline = parent_scan_id
    if default_baseline is None and candidates:
        default_baseline = max(candidates, key=_created_key).id
    return LineageResponse(
        current_scan_id=current.id,
        root_scan_id=root_scan_id,
        parent_scan_id=parent_scan_id,
        default_baseline_scan_id=default_baseline,
        nodes=nodes,
    )


async def resolve_baseline_scan_id(db: AsyncSession, current: Scan, explicit: str | None) -> str | None:
    if explicit:
        return explicit
    lineage = await db.get(ScanLineage, current.id)
    return lineage.parent_scan_id if lineage else None
