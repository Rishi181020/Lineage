from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .admin_api import router as admin_router
from .agents_api import router as agents_router
from .hooks_api import router as hooks_router
from .internal_api import router as internal_router
from .state import get_state

DASHBOARD = Path(__file__).parent / "dashboard"

app = FastAPI(title="Lineage Control")
app.include_router(hooks_router)
app.include_router(agents_router)
app.include_router(admin_router)
app.include_router(internal_router)
app.mount("/static", StaticFiles(directory=DASHBOARD), name="static")


@app.on_event("startup")
async def _startup() -> None:
    import asyncio

    get_state().bus.bind_loop(asyncio.get_running_loop())


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "control"}


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(DASHBOARD / "index.html")


@app.get("/app.js", include_in_schema=False)
def dashboard_js() -> FileResponse:
    return FileResponse(DASHBOARD / "app.js", media_type="application/javascript")


@app.get("/styles.css", include_in_schema=False)
def dashboard_css() -> FileResponse:
    return FileResponse(DASHBOARD / "styles.css", media_type="text/css")
