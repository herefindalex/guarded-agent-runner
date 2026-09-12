from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from guarded_agent_runner.service import RunnerService

router = APIRouter(prefix="/approvals", tags=["approvals"])


class ApprovalDecisionRequest(BaseModel):
    actor: str = Field(default="human-operator", min_length=1, max_length=120)


def service(request: Request) -> RunnerService:
    return request.app.state.runner_service


@router.post("/{approval_id}/approve")
async def approve(approval_id: str, payload: ApprovalDecisionRequest, request: Request):
    runner = service(request)
    return runner.view(await runner.approve(approval_id, payload.actor))


@router.post("/{approval_id}/reject")
async def reject(approval_id: str, payload: ApprovalDecisionRequest, request: Request):
    runner = service(request)
    return runner.view(await runner.reject(approval_id, payload.actor))
