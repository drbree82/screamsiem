from __future__ import annotations

from typing import AsyncIterator, Protocol

from ..models import CommandResult


class SSHTransport(Protocol):
    async def run(self, argv: list[str], timeout: float = 10) -> CommandResult: ...
    async def stream(self, argv: list[str]) -> AsyncIterator[str]: ...
    async def close(self) -> None: ...
