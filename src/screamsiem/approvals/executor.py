from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from .tokens import ApprovalToken


class RemediationExecutor:
    def __init__(self, host_id: str, transport, approval_secret: str, nonce_store=None): self.host_id,self.transport,self.secret,self.nonce_store=host_id,transport,approval_secret,nonce_store

    async def execute(self, tool: str, arguments: dict, approval_token: str | None = None) -> dict:
        if tool not in {"stop_process","stop_service","restart_service"}: return {"status":"error","error":"unsupported mutable tool"}
        if not approval_token: return {"status":"approval_required","tool":tool,"host_id":self.host_id,"arguments":arguments}
        try: token=ApprovalToken.verify(approval_token,self.secret,self.host_id,tool,arguments)
        except ValueError as exc: return {"status":"approval_required","tool":tool,"host_id":self.host_id,"arguments":arguments,"error":str(exc)}
        if self.nonce_store is not None and not await self.nonce_store(token.nonce, datetime.fromtimestamp(token.expires_at, timezone.utc)): return {"status":"error","error":"approval token replayed"}
        if tool=="stop_process": return await self.stop_process(arguments)
        unit=arguments.get("unit","")
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]+",unit): return {"status":"error","error":"invalid systemd unit"}
        command=["systemctl", "stop" if tool=="stop_service" else "restart", "--", unit]; result=await self.transport.run(command,timeout=30)
        return {"status":"success" if result.exit_status==0 else "error","tool":tool,"stdout":result.stdout[:10000],"stderr":result.stderr[:10000],"exit_status":result.exit_status}

    async def stop_process(self, arguments: dict)->dict:
        try: pid=int(arguments["pid"]); expected=str(arguments["expected_start_time"])
        except (KeyError,ValueError): return {"status":"error","error":"pid and expected_start_time are required"}
        if pid<=0: return {"status":"error","error":"pid must be positive"}
        status=await self.transport.run(["cat",f"/proc/{pid}/stat"])
        if status.exit_status!=0: return {"status":"error","error":"process not found"}
        fields=status.stdout.split(); actual=fields[21] if len(fields)>21 else ""
        if actual!=expected: return {"status":"error","error":"process start time mismatch"}
        result=await self.transport.run(["kill","-TERM",str(pid)],timeout=10)
        return {"status":"success" if result.exit_status==0 else "error","tool":"stop_process","pid":pid,"stdout":result.stdout[:10000],"stderr":result.stderr[:10000],"exit_status":result.exit_status}
