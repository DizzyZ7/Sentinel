from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import get_settings
from app.core.database import engine
from app.models import Base
from app.routers.health import router as health_router
from app.routers.scans import router as scans_router

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.scans_dir.mkdir(parents=True, exist_ok=True)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="Sentinel", version="0.1.0", lifespan=lifespan)
app.include_router(health_router)
app.include_router(scans_router)
