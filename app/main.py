from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.core.config import get_settings
from app.core.database import engine
from app.core.version import APP_VERSION
from app.models import Base
from app.routers.comparison import router as comparison_router
from app.routers.demo import router as demo_router
from app.routers.evidence import router as evidence_router
from app.routers.health import router as health_router
from app.routers.judge import router as judge_router
from app.routers.lineage import router as lineage_router
from app.routers.llm_audit import router as llm_audit_router
from app.routers.progress import router as progress_router
from app.routers.project_context import router as project_context_router
from app.routers.risk_exception import router as risk_exception_router
from app.routers.risk_intelligence import router as risk_intelligence_router
from app.routers.scans import router as scans_router
from app.routers.security_policy import router as security_policy_router

settings = get_settings()
templates = Jinja2Templates(directory="app/templates")


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.scans_dir.mkdir(parents=True, exist_ok=True)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title="Sentinel",
    version=APP_VERSION,
    description="Human-in-the-loop security review agent powered by GPT-5.6",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(health_router)
app.include_router(comparison_router)
app.include_router(demo_router)
app.include_router(evidence_router)
app.include_router(judge_router)
app.include_router(lineage_router)
app.include_router(llm_audit_router)
app.include_router(progress_router)
app.include_router(project_context_router)
app.include_router(risk_exception_router)
app.include_router(risk_intelligence_router)
app.include_router(security_policy_router)
app.include_router(scans_router)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="index.html")
