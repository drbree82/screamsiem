from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable


@dataclass
class CollectorHealth:
    name: str
    state: str = "starting"
    last_success: datetime | None = None
    last_error: str | None = None
    reconnect_count: int = 0
    lag_seconds: float = 0


class Collector:
    def __init__(self, name: str, interval: float, sample: Callable[[], Awaitable[None]]):
        self.health=CollectorHealth(name); self.interval=interval; self.sample=sample; self._task: asyncio.Task|None=None; self._stop=asyncio.Event()

    async def run(self):
        self.health.state="healthy"
        while not self._stop.is_set():
            try:
                await self.sample(); self.health.last_success=datetime.now(timezone.utc); self.health.last_error=None; self.health.state="healthy"
            except asyncio.CancelledError: raise
            except Exception as exc:
                self.health.state="degraded"; self.health.last_error=str(exc); self.health.reconnect_count+=1
            try: await asyncio.wait_for(self._stop.wait(), self.interval)
            except asyncio.TimeoutError: pass
        self.health.state="stopped"

    def start(self): self._task=asyncio.create_task(self.run()); return self._task
    async def stop(self):
        self._stop.set()
        if self._task: await self._task
