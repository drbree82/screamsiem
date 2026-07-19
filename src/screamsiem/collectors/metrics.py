from __future__ import annotations

import re
import time

from ..models import MetricSample


class MetricsCollector:
    def __init__(self, transport, host_id, emit): self.transport,self.host_id,self.emit=transport,host_id,emit
    async def sample(self):
        start=time.monotonic(); result=await self.transport.run(["cat","/proc/loadavg","/proc/meminfo"]); text=result.stdout; load=0.0
        first=text.splitlines()[0] if text else ""
        try: load=float(first.split()[0])
        except (ValueError,IndexError): pass
        total=available=0
        for line in text.splitlines():
            if line.startswith("MemTotal:"): total=int(re.search(r"\d+",line).group())*1024
            elif line.startswith("MemAvailable:"): available=int(re.search(r"\d+",line).group())*1024
        ps=await self.transport.run(["ps","-e","--no-headers"]); sockets=await self.transport.run(["ss","-Htan"])
        await self.emit(MetricSample(host_id=self.host_id,load_1=load,memory_total=total,memory_used=max(0,total-available),process_count=len(ps.stdout.splitlines()),tcp_connections=len(sockets.stdout.splitlines()),collection_latency_ms=(time.monotonic()-start)*1000))
