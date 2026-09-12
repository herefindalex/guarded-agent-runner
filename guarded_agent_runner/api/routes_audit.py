from fastapi import APIRouter, Request

from guarded_agent_runner.service import RunnerService

router = APIRouter(prefix="/runs", tags=["audit"])


@router.get("/{run_id}/audit")
def get_audit(run_id: str, request: Request):
    runner: RunnerService = request.app.state.runner_service
    runner.get_run(run_id)
    return [event.model_dump(mode="json") for event in runner.repository.list_audit(run_id)]
