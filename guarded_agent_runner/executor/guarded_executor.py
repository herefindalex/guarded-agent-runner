from __future__ import annotations

import asyncio

from guarded_agent_runner.executor.infrastructure import InfrastructureAdapter
from guarded_agent_runner.models import ExecutionToken, ToolCall, utcnow

EXECUTOR_ACTIONS = {"service_status", "read_log", "restart_service"}


class ExecutionDenied(RuntimeError):
    pass


class ExecutionTimedOut(RuntimeError):
    pass


class GuardedExecutor:
    def __init__(self, infrastructure: InfrastructureAdapter, timeout_seconds: float = 2.0) -> None:
        self.infrastructure = infrastructure
        self.timeout_seconds = timeout_seconds

    async def execute(self, run_id: str, call: ToolCall, token: ExecutionToken):
        if call.action not in EXECUTOR_ACTIONS:
            raise ExecutionDenied("Action is not exposed by guarded executor")
        if call.resource is None:
            raise ExecutionDenied("Execution resource is missing")
        if (
            token.run_id != run_id
            or token.action != call.action
            or token.resource != call.resource
            or utcnow() >= token.expires_at
        ):
            raise ExecutionDenied("Execution token does not match the requested action")
        try:
            return await asyncio.wait_for(
                self.infrastructure.execute(call.action, call.args.copy()),
                timeout=self.timeout_seconds,
            )
        except TimeoutError as exc:
            raise ExecutionTimedOut("Guarded execution timed out") from exc
        finally:
            await self.infrastructure.cleanup(token.nonce)
