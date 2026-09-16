from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from guarded_agent_runner.api.routes_approvals import router as approvals_router
from guarded_agent_runner.api.routes_audit import router as audit_router
from guarded_agent_runner.api.routes_runs import router as runs_router
from guarded_agent_runner.api.routes_sandbox import router as sandbox_router
from guarded_agent_runner.executor.sandbox_http import SandboxHTTPInfrastructure
from guarded_agent_runner.service import RunnerError, RunnerService
from guarded_agent_runner.storage.repository import Repository

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"


def create_app(repository: Repository | None = None, runner_service: RunnerService | None = None) -> FastAPI:
    app = FastAPI(
        title="Guarded Agent Runner",
        version="0.1.0",
        description="Capability-scoped, human-approved infrastructure action runner",
    )
    repository = repository or Repository(os.getenv("DATABASE_URL", "sqlite:///./guarded_agent_runner.db"))
    if runner_service is None:
        sandbox_url = os.getenv("SANDBOX_SERVICE_URL")
        infrastructure = SandboxHTTPInfrastructure(sandbox_url) if sandbox_url else None
        runner_service = RunnerService(repository, infrastructure=infrastructure)
    app.state.runner_service = runner_service

    app.include_router(runs_router)
    app.include_router(approvals_router)
    app.include_router(audit_router)
    if os.getenv("DEMO_MODE", "").lower() in {"1", "true", "yes"}:
        app.include_router(sandbox_router)

    @app.exception_handler(RunnerError)
    async def runner_error_handler(_: Request, exc: RunnerError):
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})

    @app.get("/health", tags=["system"])
    def health():
        return {"status": "ok"}

    if (FRONTEND_DIST / "assets").exists():
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    def frontend():
        index = FRONTEND_DIST / "index.html"
        if index.exists():
            return FileResponse(index)
        return {
            "name": "Guarded Agent Runner",
            "message": "Build the React frontend with `npm --prefix frontend run build`.",
            "docs": "/docs",
        }

    return app
