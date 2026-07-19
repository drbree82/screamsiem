from __future__ import annotations

from ..events import make_event


class FileTailCollector:
    def __init__(self, transport, host_id, path, emit): self.transport,self.host_id,self.path,self.emit=transport,host_id,path,emit
    async def run(self):
        async for line in self.transport.stream(["tail","-n","0","-F","--",self.path]):
            await self.emit(make_event(self.host_id,"file", "log_message", line, {"path":self.path,"message":line},"low",raw_excerpt=line))
