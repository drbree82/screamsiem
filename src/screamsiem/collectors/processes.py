from __future__ import annotations

from ..events import make_event
from ..parsers.ps import parse_ps, process_fingerprint


class ProcessCollector:
    def __init__(self, transport, host_id, emit, baseline=None):
        self.transport,self.host_id,self.emit=transport,host_id,emit
        self.previous: dict[int,str]={p["pid"]:p.get("fingerprint") or process_fingerprint(p) for p in (baseline or []) if "pid" in p}

    async def sample(self):
        result=await self.transport.run(["ps","-eo","pid,ppid,user,etimes,comm,args","--no-headers"]); current={}
        for p in parse_ps(result.stdout):
            fp=process_fingerprint(p); current[p["pid"]]=fp
            if self.previous.get(p["pid"]) != fp:
                await self.emit(make_event(self.host_id,"process","process_started",f"{p['command']} started as {p['user']}",{**p,"fingerprint":fp},"high" if p["suspicious_path"] else "low"))
        self.previous=current
