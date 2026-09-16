from __future__ import annotations

import socket

import pytest

from guarded_agent_runner.executor.sandbox_http import SandboxHTTPInfrastructure
from guarded_agent_runner.sandbox.service import SandboxManager


def available_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.asyncio
async def test_fixed_sandbox_replaces_a_real_process_and_reports_logs():
    manager = SandboxManager(worker_port=available_port())
    try:
        initial = await manager.start(healthy=False)
        assert initial["status"] == "unhealthy"
        assert initial["pid"] is not None
        assert initial["generation"] == 1

        restarted = await manager.restart()
        assert restarted["status"] == "healthy"
        assert restarted["pid"] != initial["pid"]
        assert restarted["previous_pid"] == initial["pid"]
        assert restarted["generation"] == 2
        assert any("restart_completed" in line for line in restarted["lines"])

        reset = await manager.reset()
        assert reset["status"] == "unhealthy"
        assert reset["pid"] != restarted["pid"]
        assert reset["generation"] == 3
    finally:
        await manager.stop()


@pytest.mark.asyncio
async def test_sandbox_adapter_exposes_only_service_a(monkeypatch):
    adapter = SandboxHTTPInfrastructure("http://sandbox.invalid")

    async def request(method: str, path: str):
        if path == "/status":
            return {"service": "service-a", "status": "unhealthy", "pid": 10, "generation": 1}
        if path == "/restart":
            return {
                "service": "service-a",
                "status": "healthy",
                "pid": 11,
                "previous_pid": 10,
                "generation": 2,
                "restarted": True,
            }
        return {"service": "service-a", "lines": ["sandbox log"]}

    monkeypatch.setattr(adapter, "_request", request)

    status = await adapter.execute("service_status", {"service": "service-a"})
    assert status["status"] == "degraded"
    assert status["health"] == "unhealthy"

    restarted = await adapter.execute("restart_service", {"service": "service-a"})
    assert restarted["status"] == "running"
    assert restarted["health"] == "healthy"

    snapshot = await adapter.snapshot()
    assert snapshot["status"] == "unhealthy"
    assert snapshot["lines"] == ["sandbox log"]

    with pytest.raises(ValueError, match="only exposes service-a"):
        await adapter.execute("service_status", {"service": "nginx"})
