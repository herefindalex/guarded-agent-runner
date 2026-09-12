import pytest

from guarded_agent_runner.models import AuditEventType, RunStatus, ToolCall
from guarded_agent_runner.planner.deterministic_planner import DeterministicPlanner
from guarded_agent_runner.policy.policy_engine import PolicyEngine
from guarded_agent_runner.service import RunnerService


@pytest.mark.asyncio
async def test_policy_exception_fails_closed(repository, infrastructure):
    runner = RunnerService(
        repository,
        planner=DeterministicPlanner([ToolCall(action="service_status", args={"service": "nginx"})]),
        policy=PolicyEngine(force_failure=True),
        infrastructure=infrastructure,
    )
    run = runner.create_run("alex", "Check nginx")
    run = await runner.step(run.id)

    assert run.status is RunStatus.FAILED
    assert infrastructure.executed_actions == []
    events = repository.list_audit(run.id)
    denied = next(event for event in events if event.event_type is AuditEventType.TOOL_DENIED)
    assert denied.metadata["decision"] == "DENY_INTERNAL_ERROR"
