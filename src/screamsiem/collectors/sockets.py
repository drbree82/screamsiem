from __future__ import annotations

from ..events import make_event
from ..parsers.ss import parse_ss


class SocketCollector:
    def __init__(self, transport, host_id, emit): self.transport,self.host_id,self.emit=transport,host_id,emit; self.previous=set()
    async def sample(self):
        result=await self.transport.run(["ss","-Hltunp"]); records=parse_ss(result.stdout, listening=True); current=set()
        for s in records:
            key=f"{s.get('protocol')}|{s.get('local_address')}|{s.get('port')}|{s.get('pid')}|{s.get('process')}"; current.add(key)
            if key not in self.previous:
                data={"address":s.get("local_address"),"port":s.get("port"),"pid":s.get("pid"),"process":s.get("process"),"protocol":s.get("protocol"),"command":s.get("command","")}; await self.emit(make_event(self.host_id,"socket","new_listening_socket",f"{s.get('process','unknown')} began listening on {s.get('local_address')}:{s.get('port')}",data,"high" if s.get("local_address") in {"0.0.0.0","::"} else "medium",raw_excerpt=s.get("raw","")))
        self.previous=current
