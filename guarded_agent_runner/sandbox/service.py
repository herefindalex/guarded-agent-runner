from __future__ import annotations

import asyncio
import json
import os
import sys
from collections import deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from fastapi import FastAPI, Query, Request


def utc_timestamp() -> str:
    return datetime.now(UTC).isoformat()


class SandboxManager:
    def __init__(self, *, worker_port: int = 9100) -> None:
        self.worker_port = worker_port
        self.generation = 0
        self.process: asyncio.subprocess.Process | None = None
        self.logs: deque[str] = deque(maxlen=1000)
        self._output_task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    async def start(self, *, healthy: bool) -> dict[str, Any]:
        async with self._lock:
            return await self._replace(healthy=healthy, event="sandbox_started")

    async def restart(self) -> dict[str, Any]:
        async with self._lock:
            previous_pid = self.process.pid if self.process else None
            result = await self._replace(healthy=True, event="restart_completed")
            result.update({"restarted": True, "previous_pid": previous_pid})
            result["lines"] = list(self.logs)[-100:]
            return result

    async def reset(self) -> dict[str, Any]:
        async with self._lock:
            previous_pid = self.process.pid if self.process else None
            result = await self._replace(healthy=False, event="demo_reset")
            result.update({"reset": True, "previous_pid": previous_pid})
            return result

    async def stop(self) -> None:
        async with self._lock:
            await self._stop_process()

    async def status(self) -> dict[str, Any]:
        process = self.process
        if process is None or process.returncode is not None:
            return {
                "service": "service-a",
                "status": "unavailable",
                "pid": None,
                "generation": self.generation,
                "observed_at": utc_timestamp(),
            }

        payload = await asyncio.to_thread(self._probe_worker)
        return {
            "service": "service-a",
            "status": payload.get("status", "unavailable"),
            "pid": process.pid,
            "generation": self.generation,
            "observed_at": utc_timestamp(),
        }

    def recent_logs(self, lines: int) -> dict[str, Any]:
        return {
            "service": "service-a",
            "lines": list(self.logs)[-lines:],
            "observed_at": utc_timestamp(),
        }

    async def _replace(self, *, healthy: bool, event: str) -> dict[str, Any]:
        await self._stop_process()
        self.generation += 1
        command = [
            sys.executable,
            "-m",
            "guarded_agent_runner.sandbox.worker",
            "--port",
            str(self.worker_port),
            "--generation",
            str(self.generation),
        ]
        if healthy:
            command.append("--healthy")

        self.process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._append_log(
            event,
            pid=self.process.pid,
            generation=self.generation,
            requested_state="healthy" if healthy else "unhealthy",
        )
        self._output_task = asyncio.create_task(self._capture_output(self.process))
        await self._wait_until_reachable()
        return await self.status()

    async def _stop_process(self) -> None:
        process = self.process
        if process is None:
            return
        if process.returncode is None:
            self._append_log("worker_stopping", pid=process.pid, generation=self.generation)
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()
                await process.wait()
        if self._output_task:
            await self._output_task
        self.process = None
        self._output_task = None

    async def _capture_output(self, process: asyncio.subprocess.Process) -> None:
        if process.stdout is None:
            return
        while line := await process.stdout.readline():
            self.logs.append(f"{utc_timestamp()} worker {line.decode().rstrip()}")

    async def _wait_until_reachable(self) -> None:
        for _ in range(30):
            try:
                await asyncio.to_thread(self._probe_worker)
                return
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
                await asyncio.sleep(0.1)
        raise RuntimeError("Sandbox worker did not become reachable")

    def _probe_worker(self) -> dict[str, Any]:
        try:
            with urlopen(f"http://127.0.0.1:{self.worker_port}/health", timeout=0.5) as response:
                payload = response.read()
        except HTTPError as exc:
            payload = exc.read()
        return json.loads(payload.decode("utf-8"))

    def _append_log(self, event: str, **metadata: Any) -> None:
        payload = json.dumps({"event": event, **metadata}, sort_keys=True)
        self.logs.append(f"{utc_timestamp()} supervisor {payload}")


def create_app() -> FastAPI:
    manager = SandboxManager(worker_port=int(os.getenv("SANDBOX_WORKER_PORT", "9100")))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.manager = manager
        await manager.start(healthy=False)
        try:
            yield
        finally:
            await manager.stop()

    app = FastAPI(title="Guarded Agent Runner Demo Sandbox", version="0.1.0", lifespan=lifespan)

    @app.get("/status")
    async def status(request: Request):
        return await request.app.state.manager.status()

    @app.get("/logs")
    async def logs(request: Request, lines: int = Query(default=100, ge=1, le=1000)):
        return request.app.state.manager.recent_logs(lines)

    @app.post("/restart")
    async def restart(request: Request):
        return await request.app.state.manager.restart()

    @app.post("/reset")
    async def reset(request: Request):
        return await request.app.state.manager.reset()

    return app
