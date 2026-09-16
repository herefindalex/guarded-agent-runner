from __future__ import annotations

from typing import Any, Protocol


class InfrastructureAdapter(Protocol):
    async def execute(self, action: str, args: dict[str, Any]) -> Any: ...

    async def cleanup(self, token_nonce: str) -> None: ...

