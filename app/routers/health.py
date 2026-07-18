from fastapi import APIRouter

from app.core.version import APP_VERSION

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel", "version": APP_VERSION}
