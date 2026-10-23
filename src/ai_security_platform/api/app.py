from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ai_security_platform.api.errors import ErrorResponse, register_handlers
from ai_security_platform.api.routes import (
    findings,
    health,
    launcher,
    projects,
    scan_runs,
    snapshots,
    triage,
)
from ai_security_platform.api.security import BoundaryMiddleware
from ai_security_platform.config import Settings, load_settings
from ai_security_platform.logging import configure_logging
from ai_security_platform.snapshots.store import SnapshotStore
from ai_security_platform.storage.readiness import DatabaseReadiness
from ai_security_platform.storage.session import build_engine, session_factory


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    configure_logging()
    engine = build_engine(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(
        title="AI Security Platform",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
        redirect_slashes=False,
        responses={
            code: {"model": ErrorResponse}
            for code in (400, 401, 403, 404, 408, 409, 413, 422, 429, 500, 503)
        },
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.readiness = DatabaseReadiness()
    app.state.session_factory = session_factory(engine)
    app.state.snapshot_store = SnapshotStore(settings.snapshot_spool)
    register_handlers(app)
    app.add_middleware(BoundaryMiddleware, settings=settings)
    app.include_router(health.router)
    app.include_router(projects.router)
    app.include_router(scan_runs.router)
    app.include_router(snapshots.router)
    app.include_router(launcher.router)
    app.include_router(findings.router)
    app.include_router(triage.router)
    return app
