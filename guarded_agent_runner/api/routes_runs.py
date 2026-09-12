from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from guarded_agent_runner.models import PlanPreset, ServiceName
from guarded_agent_runner.service import RunnerService

router = APIRouter(prefix="/runs", tags=["runs"])


class CreateRunRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=120)
    request: str = Field(min_length=1, max_length=4000)
    workflow: PlanPreset = PlanPreset.DIAGNOSE_AND_RESTART
    target_service: ServiceName = ServiceName.NGINX


def service(request: Request) -> RunnerService:
    return request.app.state.runner_service


@router.post("")
def create_run(payload: CreateRunRequest, request: Request):
    runner = service(request)
    return runner.view(
        runner.create_run(
            payload.user_id,
            payload.request,
            payload.workflow,
            payload.target_service,
        )
    )


@router.post("/{run_id}/step")
async def step_run(run_id: str, request: Request):
    runner = service(request)
    return runner.view(await runner.step(run_id))


@router.post("/{run_id}/run")
async def run_until_blocked(run_id: str, request: Request):
    runner = service(request)
    return runner.view(await runner.run_until_blocked(run_id))


@router.get("/{run_id}")
def get_run(run_id: str, request: Request):
    runner = service(request)
    return runner.view(runner.get_run(run_id))
