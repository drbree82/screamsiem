from __future__ import annotations

from ..events import make_event


class ServiceCollector:
    def __init__(self, transport, host_id, emit, baseline=None):
        self.transport,self.host_id,self.emit=transport,host_id,emit
        self.previous={s.get("unit"):s.get("state") for s in (baseline or []) if s.get("unit")}
    async def sample(self):
        result=await self.transport.run(["systemctl","list-units","--type=service","--all","--no-legend","--no-pager"]); current={}
        for line in result.stdout.splitlines():
            parts=line.split();
            if not parts: continue
            unit=parts[0]; state=parts[2] if len(parts)>2 else "unknown"; current[unit]=state
            if unit in self.previous and self.previous[unit]!=state:
                await self.emit(make_event(self.host_id,"service","failed_service" if state=="failed" else "changed_service",f"{unit} changed state to {state}",{"unit":unit,"state":state,"previous_state":self.previous[unit]},"high" if state=="failed" else "medium"))
            elif unit not in self.previous:
                await self.emit(make_event(self.host_id,"service","new_service",f"New service {unit} is {state}",{"unit":unit,"state":state},"high"))
        self.previous=current
