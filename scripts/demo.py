from __future__ import annotations

import asyncio

from guarded_agent_runner.executor.fake_infra import FakeInfrastructure
from guarded_agent_runner.models import ServiceName, ToolCall
from guarded_agent_runner.planner.deterministic_planner import DeterministicPlanner
from guarded_agent_runner.service import RunnerService
from guarded_agent_runner.storage.repository import Repository


async def normal_flow() -> None:
    repository = Repository.in_memory()
    runner = RunnerService(repository)
    run = runner.create_run(
        "demo-operator",
        "Check PostgreSQL and restart it if necessary",
        target_service=ServiceName.POSTGRESQL,
    )
    print(f"normal: created {run.id} [{run.status}]")
    while run.status.value in {"PLANNED", "RUNNING"}:
        run = await runner.step(run.id)
        print(f"normal: step -> {run.status}")
    approval = repository.pending_approval_for_run(run.id)
    print(f"normal: approval {approval.id} bound to {approval.binding_hash[:16]}...")
    await runner.approve(approval.id, "demo-operator")
    print("normal: approved, no action executed yet")
    run = await runner.step(run.id)
    print(f"normal: revalidated and resumed -> {run.status}")
    print(f"normal: audit events={len(repository.list_audit(run.id))}")
    repository.close()


async def denied_flow() -> None:
    repository = Repository.in_memory()
    infrastructure = FakeInfrastructure()
    runner = RunnerService(
        repository,
        planner=DeterministicPlanner([ToolCall(action="restart_service", args={"service": "ssh"})]),
        infrastructure=infrastructure,
    )
    run = runner.create_run("compromised-planner-demo", "Restart SSH")
    run = await runner.step(run.id)
    print(f"denied: status={run.status}, reason={run.plan[0].failure_reason}")
    print(f"denied: executor calls={len(infrastructure.executed_actions)}")
    repository.close()


async def main() -> None:
    await normal_flow()
    print()
    await denied_flow()


if __name__ == "__main__":
    asyncio.run(main())
