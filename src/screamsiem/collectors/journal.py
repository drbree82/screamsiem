from __future__ import annotations

from ..events import make_event
from ..parsers.journal import parse_journal_line


class JournalCollector:
    def __init__(self, transport, host_id, emit): self.transport,self.host_id,self.emit=transport,host_id,emit
    async def run(self):
        async for line in self.transport.stream(["journalctl","-f","-n","0","-o","json","--no-pager"]):
            item=parse_journal_line(line)
            if item:
                msg=item["message"]; lower=msg.lower()
                if "failed password" in lower or "authentication failure" in lower:
                    await self.emit(make_event(self.host_id,"journal","ssh_auth_failure",msg,{"source_ip":_source_ip(msg),"message":msg},"high",raw_excerpt=msg))
                else:
                    await self.emit(make_event(self.host_id,"journal","log_message",msg,{"unit":item.get("unit"),"priority":item.get("priority"),"message":msg},"low",raw_excerpt=msg))


def _source_ip(message: str) -> str:
    import re
    m=re.search(r"(?:from|rhost=)\s*([0-9a-fA-F:.]+)",message); return m.group(1) if m else "unknown"
