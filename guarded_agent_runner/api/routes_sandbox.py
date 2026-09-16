from fastapi import APIRouter, Query, Request

from guarded_agent_runner.service import RunnerService

router = APIRouter(prefix="/sandbox", tags=["sandbox-demo"])


def service(request: Request) -> RunnerService:
    return request.app.state.runner_service


@router.get("")
async def snapshot(request: Request, lines: int = Query(default=100, ge=1, le=1000)):
    return await service(request).sandbox_snapshot(lines=lines)


@router.post("/reset")
async def reset(request: Request):
    return await service(request).reset_sandbox()

