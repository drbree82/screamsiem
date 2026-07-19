from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from collections.abc import AsyncIterator

from ..models import CommandResult


class FakeSSHTransport:
    """Offline transport used by the demo and tests.

    Responses are selected by the first matching command token. Streams can be
    fed after construction, which makes a suspicious listener demo deterministic.
    """

    def __init__(self, responses: dict[str, str | CommandResult] | None = None):
        self.responses = responses or {}
        self.streams: dict[str, asyncio.Queue[str | None]] = defaultdict(asyncio.Queue)
        self.commands: list[list[str]] = []
        self.closed = False

    async def run(self, argv: list[str], timeout: float = 10) -> CommandResult:
        self.commands.append(argv)
        key = next((k for k in self.responses if k in argv or k in " ".join(argv)), None)
        response = self.responses.get(key or "", "")
        return response if isinstance(response, CommandResult) else CommandResult(stdout=response)

    async def stream(self, argv: list[str]) -> AsyncIterator[str]:
        key = next((k for k in self.responses if k in argv or k in " ".join(argv)), "stream")
        queue = self.streams[key]
        while not self.closed:
            line = await queue.get()
            if line is None:
                return
            yield line

    async def feed(self, key: str, line: str) -> None:
        await self.streams[key].put(line)

    async def end_stream(self, key: str) -> None:
        await self.streams[key].put(None)

    async def close(self) -> None:
        self.closed = True
