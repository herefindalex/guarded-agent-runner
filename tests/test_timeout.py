import pytest

from guarded_agent_runner.executor.fake_infra import FakeInfrastructure
from guarded_agent_runner.models import RunStatus, ToolCall
from guarded_agent_runner.planner.deterministic_planner import DeterministicPlanner
from guarded_agent_runner.service import RunnerService


@pytest.mark.asyncio
async def test_execution_timeout_fails_safely(repository):
    infrastructure = FakeInfrastructure(delays={"service_status": 0.05})
    runner = RunnerService(
        repository,
        planner=DeterministicPlanner([ToolCall(action="service_status", args={"service": "nginx"})]),
        infrastructure=infrastructure,
        execution_timeout_seconds=0.001,
    )
    run = runner.create_run("alex", "Check nginx")
    result = await runner.step(run.id)

    assert result.status is RunStatus.FAILED
    assert result.plan[0].failure_reason == "ExecutionTimedOut"
    assert infrastructure.executed_actions == []
    assert infrastructure.cleanup_calls == 1


@pytest.mark.asyncio
async def test_cleanup_is_idempotent(repository):
    infrastructure = FakeInfrastructure()
    runner = RunnerService(
        repository,
        planner=DeterministicPlanner([ToolCall(action="service_status", args={"service": "nginx"})]),
        infrastructure=infrastructure,
    )
    run = runner.create_run("alex", "Check nginx")
    await runner.step(run.id)
    assert infrastructure.cleanup_calls == 1

    token_nonce = next(iter(infrastructure._cleaned_tokens))
    await infrastructure.cleanup(token_nonce)
    assert infrastructure.cleanup_calls == 1
