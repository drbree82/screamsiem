from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator

from ..models import CommandResult


class AsyncSSHTransport:
    def __init__(self, address: str, username: str, port: int, identity_path: str,
                 known_hosts_path: str | None = None, insecure: bool = False):
        self.address, self.username, self.port, self.identity_path = address, username, port, identity_path
        self.known_hosts_path, self.insecure = known_hosts_path, insecure
        self._conn = None

    async def _connection(self):
        if self._conn and not self._conn.is_closed():
            return self._conn
        try:
            import asyncssh
        except ImportError as exc:
            raise RuntimeError("asyncssh is required for real SSH connections") from exc
        options={"port":self.port,"username":self.username,"client_keys":[self.identity_path]}
        if self.insecure: options["known_hosts"]=None
        elif self.known_hosts_path: options["known_hosts"]=self.known_hosts_path
        self._conn = await asyncssh.connect(self.address, **options)
        return self._conn

    async def run(self, argv: list[str], timeout: float = 10) -> CommandResult:
        started = time.monotonic()
        command = _argv_to_fixed_command(argv)
        try:
            result = await asyncio.wait_for((await self._connection()).run(command, check=False), timeout)
            return CommandResult(stdout=result.stdout[-1_000_000:], stderr=result.stderr[-20_000:], exit_status=result.exit_status, duration_ms=(time.monotonic()-started)*1000)
        except asyncio.TimeoutError:
            return CommandResult(stderr="command timed out", exit_status=124, timed_out=True, duration_ms=(time.monotonic()-started)*1000)

    async def stream(self, argv: list[str]) -> AsyncIterator[str]:
        process = await (await self._connection()).create_process(_argv_to_fixed_command(argv))
        async for line in process.stdout:
            yield line.rstrip("\n")

    async def close(self) -> None:
        if self._conn:
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None


def _argv_to_fixed_command(argv: list[str]) -> str:
    """Quote argv for the unavoidable SSH remote command boundary."""
    import shlex
    return " ".join(shlex.quote(str(arg)) for arg in argv)
