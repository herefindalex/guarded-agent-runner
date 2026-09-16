from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class SandboxUnavailable(RuntimeError):
    pass


class SandboxHTTPInfrastructure:
    """Narrow adapter for the fixed service-a demo sandbox."""

    def __init__(self, base_url: str, *, request_timeout_seconds: float = 1.5) -> None:
        self.base_url = base_url.rstrip("/")
        self.request_timeout_seconds = request_timeout_seconds

    async def execute(self, action: str, args: dict[str, Any]) -> Any:
        service = args.get("service")
        if service != "service-a":
            raise ValueError("Sandbox adapter only exposes service-a")

        if action == "service_status":
            return self._normalize_runner_status(await self._request("GET", "/status"))
        if action == "read_log":
            lines = int(args["lines"])
            return await self._request("GET", f"/logs?{urlencode({'lines': lines})}")
        if action == "restart_service":
            return self._normalize_runner_status(await self._request("POST", "/restart"))
        raise ValueError(f"Sandbox adapter does not expose action: {action}")

    async def snapshot(self, *, lines: int = 100) -> dict[str, Any]:
        status, logs = await asyncio.gather(
            self._request("GET", "/status"),
            self._request("GET", f"/logs?{urlencode({'lines': lines})}"),
        )
        return {**status, "lines": logs.get("lines", [])}

    async def reset(self) -> dict[str, Any]:
        return await self._request("POST", "/reset")

    async def cleanup(self, token_nonce: str) -> None:
        del token_nonce

    @staticmethod
    def _normalize_runner_status(payload: dict[str, Any]) -> dict[str, Any]:
        health = payload.get("status")
        normalized = "running" if health == "healthy" else "degraded"
        return {**payload, "health": health, "status": normalized}

    async def _request(self, method: str, path: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._request_sync, method, path)

    def _request_sync(self, method: str, path: str) -> dict[str, Any]:
        request = Request(f"{self.base_url}{path}", method=method)
        try:
            with urlopen(request, timeout=self.request_timeout_seconds) as response:
                payload = response.read().decode("utf-8")
        except (HTTPError, URLError, TimeoutError) as exc:
            raise SandboxUnavailable(f"Sandbox request failed: {method} {path}") from exc

        value = json.loads(payload)
        if not isinstance(value, dict):
            raise SandboxUnavailable("Sandbox returned a non-object response")
        return value
