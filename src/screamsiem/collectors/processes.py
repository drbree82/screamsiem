from __future__ import annotations

from ..events import make_event
from ..parsers.ps import parse_ps, process_fingerprint


class ProcessCollector:
    def __init__(self, transport, host_id, emit):
        self.transport,self.host_id,self.emit=transport,host_id,emit; self.previous: dict[int,str]={}

    async def sample(self):
        result=await self.transport.run(["ps","-eo","pid,ppid,user,etimes,comm,args","--no-headers"]); current={}
        for p in parse_ps(result.stdout):
            fp=process_fingerprint(p); current[p["pid"]]=fp
            if p["pid"] not in self.previous:
                await self.emit(make_event(self.host_id,"process","process_started",f"{p['command']} started as {p['user']}",{**p,"fingerprint":fp},"high" if p["suspicious_path"] else "low"))
        self.previous=current
