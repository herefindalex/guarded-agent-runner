from __future__ import annotations

import asyncio
from copy import deepcopy
from typing import Any


class FakeInfrastructure:
    def __init__(self, delays: dict[str, float] | None = None) -> None:
        self.services: dict[str, dict[str, Any]] = {
            "nginx": {
                "status": "stopped",
                "logs": ["2026-09-12 nginx failed to bind port"],
            },
            "postgresql": {
                "status": "degraded",
                "logs": ["2026-09-12 PostgreSQL recovery process is repeatedly restarting"],
            },
            "mysql": {
                "status": "running",
                "logs": ["2026-09-12 MySQL ready for connections"],
            },
            "redis": {
                "status": "running",
                "logs": ["2026-09-12 Redis ready to accept connections"],
            },
        }
        self.delays = delays or {}
        self.executed_actions: list[tuple[str, dict[str, Any]]] = []
        self._cleaned_tokens: set[str] = set()
        self.cleanup_calls = 0

    async def execute(self, action: str, args: dict[str, Any]) -> Any:
        delay = self.delays.get(action, 0)
        if delay:
            await asyncio.sleep(delay)
        service = args["service"]
        if service not in self.services:
            raise ValueError("Unknown infrastructure resource")
        self.executed_actions.append((action, deepcopy(args)))
        if action == "service_status":
            return {"service": service, "status": self.services[service]["status"]}
        if action == "read_log":
            lines = args["lines"]
            return {"service": service, "lines": self.services[service]["logs"][-lines:]}
        if action == "restart_service":
            self.services[service]["status"] = "running"
            return {"service": service, "status": "running", "restarted": True}
        raise ValueError("Executor does not expose this action")

    async def cleanup(self, token_nonce: str) -> None:
        if token_nonce in self._cleaned_tokens:
            return
        self._cleaned_tokens.add(token_nonce)
        self.cleanup_calls += 1
