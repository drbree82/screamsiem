from __future__ import annotations

import asyncio
import os
import re
import socket
from datetime import datetime, timezone

from ..baselines.service import BaselineService
from ..collectors.base import Collector
from ..collectors.metrics import MetricsCollector
from ..collectors.processes import ProcessCollector
from ..collectors.services import ServiceCollector
from ..collectors.sockets import SocketCollector
from ..parsers.passwd import parse_passwd
from ..parsers.ps import parse_ps
from ..parsers.ss import parse_ss
from ..approvals.executor import RemediationExecutor


class HostBridge:
    """One-host boundary. The central server may only use the typed methods below."""
    def __init__(self, host_id, transport, port=9100, central_emit=None, approval_secret="", log_allowlist=None):
        self.host_id,self.transport,self.port=host_id,transport,port; self.central_emit=central_emit; self.approval_secret=approval_secret; self.log_allowlist=set(log_allowlist or []); self.profile_data={}; self.baseline={}; self.collectors=[]; self.stream_tasks=[]; self.used_nonces=set(); self.executor=RemediationExecutor(host_id,transport,approval_secret,self._remember_nonce); self.started=False
    def ensure_loopback(self, bind_address="127.0.0.1", development_override=False):
        if bind_address not in {"127.0.0.1","::1","localhost"} and not development_override: raise ValueError("host bridge MCP must bind to loopback")
    async def start(self):
        self.ensure_loopback(); self.profile_data=await BaselineService(self.transport).profile(); self.started=True
    async def stop(self):
        for c in self.collectors: await c.stop()
        for task in self.stream_tasks: task.cancel()
        await self.transport.close(); self.started=False
    async def create_baseline(self): self.baseline=self.profile_data or await BaselineService(self.transport).profile(); return self.baseline
    def read_tools(self)->set[str]: return {"host_profile","list_processes","inspect_process","list_listening_sockets","list_connections","read_journal","read_log","list_services","service_status","list_users","get_metrics"}
    def read_tool_schemas(self):
        return [("host_profile","Return bounded host identity and visibility information",{"type":"object","properties":{}}),("list_processes","List bounded processes",{"type":"object","properties":{"filter":{"type":["string","null"]},"limit":{"type":"integer","maximum":200}}}),("inspect_process","Inspect one process without returning its environment",{"type":"object","required":["pid"],"properties":{"pid":{"type":"integer"}}}),("list_listening_sockets","List listening sockets",{"type":"object","properties":{}}),("list_connections","List bounded network connections",{"type":"object","properties":{"limit":{"type":"integer","maximum":500}}}),("read_journal","Read bounded journal evidence",{"type":"object","required":["since"],"properties":{"since":{"type":"string"},"unit":{"type":["string","null"]},"priority":{"type":["string","null"]},"limit":{"type":"integer","maximum":200}}}),("read_log","Read an allowlisted log",{"type":"object","required":["path"],"properties":{"path":{"type":"string"},"lines":{"type":"integer","maximum":200}}}),("list_services","List systemd services",{"type":"object","properties":{"state":{"type":["string","null"]}}}),("service_status","Read bounded service status",{"type":"object","required":["unit"],"properties":{"unit":{"type":"string"}}}),("list_users","List users",{"type":"object","properties":{}}),("get_metrics","Read current metrics",{"type":"object","properties":{}})]
    async def call_read_tool(self,name,arguments):
        if name not in self.read_tools(): raise ValueError("unknown or mutable tool")
        a=arguments or {}; limit=max(1,min(int(a.get("limit",200)),500))
        if name=="host_profile": return self.profile_data
        if name=="list_processes":
            records=parse_ps((await self.transport.run(["ps","-eo","pid,ppid,user,etimes,comm,args","--no-headers"])).stdout); f=a.get("filter"); return [x for x in records if not f or f.lower() in x["command"].lower()][:limit]
        if name=="inspect_process": return await self._inspect_process(int(a.get("pid",0)))
        if name=="list_listening_sockets": return parse_ss((await self.transport.run(["ss","-Hltunp"])).stdout,True)
        if name=="list_connections": return parse_ss((await self.transport.run(["ss","-Htuna"])).stdout)[:limit]
        if name=="read_journal":
            argv=["journalctl","--since",str(a.get("since","-15 minutes")),"--no-pager","-n",str(limit)];
            if a.get("unit"): argv += ["-u",str(a["unit"])]
            if a.get("priority"): argv += ["-p",str(a["priority"])]
            return {"lines":(await self.transport.run(argv)).stdout[-50000:]}
        if name=="read_log":
            path=str(a.get("path"));
            if path not in self.log_allowlist: raise ValueError("log path is not allowlisted")
            return {"path":path,"lines":(await self.transport.run(["tail","-n",str(min(int(a.get("lines",200)),200)),"--",path])).stdout[-50000:]}
        if name=="list_services": return {"services":(await self.transport.run(["systemctl","list-units","--type=service","--all","--no-legend","--no-pager"])).stdout[:50000]}
        if name=="service_status":
            unit=str(a.get("unit"));
            if not re.fullmatch(r"[A-Za-z0-9_.@:-]+",unit): raise ValueError("invalid systemd unit")
            return {"status":(await self.transport.run(["systemctl","status","--no-pager","--",unit])).stdout[-20000:]}
        if name=="list_users": return parse_passwd((await self.transport.run(["getent","passwd"])).stdout)
        if name=="get_metrics": return {"loadavg":(await self.transport.run(["cat","/proc/loadavg"])).stdout[:1000]}
        raise ValueError("unhandled tool")
    async def _inspect_process(self,pid:int):
        if pid<=0: raise ValueError("pid must be positive")
        result=await self.transport.run(["ps","-o","pid=,ppid=,user=,etime=,args=","-p",str(pid)]); return {"pid":pid,"process":result.stdout[:10000],"start_time_guard":(await self.transport.run(["awk", "{print $22}",f"/proc/{pid}/stat"])).stdout.strip()}
    async def call_mutable(self,name,arguments,approval_token=None): return await self.executor.execute(name,arguments,approval_token)
    async def start_collectors(self, baseline=None):
        self.baseline=baseline or self.baseline
        async def event(e):
            if self.central_emit: await self.central_emit(e)
        async def metric(m):
            if self.central_emit: await self.central_emit(m)
        for collector in [Collector("process",5,ProcessCollector(self.transport,self.host_id,event).sample),Collector("socket",5,SocketCollector(self.transport,self.host_id,event).sample),Collector("service",30,ServiceCollector(self.transport,self.host_id,event).sample),Collector("metrics",2,MetricsCollector(self.transport,self.host_id,metric).sample)]: collector.start(); self.collectors.append(collector)
        from ..collectors.file_tail import FileTailCollector
        from ..collectors.journal import JournalCollector
        journal=JournalCollector(self.transport,self.host_id,event); self.stream_tasks.append(asyncio.create_task(journal.run()))
        for path in self.log_allowlist: self.stream_tasks.append(asyncio.create_task(FileTailCollector(self.transport,self.host_id,path,event).run()))

    async def _remember_nonce(self, nonce, expires_at):
        if nonce in self.used_nonces: return False
        self.used_nonces.add(nonce); return True


def create_mcp_app(bridge: HostBridge):
    from fastapi import FastAPI, HTTPException
    app=FastAPI(title=f"ScreamSIEM host bridge {bridge.host_id}")
    @app.get("/healthz")
    async def healthz(): return {"status":"ok","host_id":bridge.host_id,"port":bridge.port}
    @app.post("/mcp")
    async def mcp_call(payload: dict):
        name=payload.get("tool"); arguments=payload.get("arguments") or {}
        try:
            if name in bridge.read_tools(): result=await bridge.call_read_tool(name,arguments)
            elif name in {"stop_process","stop_service","restart_service"}: result=await bridge.call_mutable(name,arguments,payload.get("approval_token"))
            else: raise HTTPException(404,"unknown tool")
            return {"tool":name,"result":result}
        except ValueError as exc: raise HTTPException(400,str(exc)) from exc
    return app


def create_fastmcp_server(bridge: HostBridge):
    """Build the official MCP SDK server for deployments using Streamable HTTP.

    The compact JSON route above is useful for local health checks and tests;
    this adapter exposes the same typed boundary through FastMCP without ever
    registering a generic shell tool.
    """
    from mcp.server.fastmcp import FastMCP
    mcp=FastMCP(f"screamsiem-{bridge.host_id}",host="127.0.0.1",port=bridge.port)
    @mcp.tool()
    async def host_profile()->dict: return await bridge.call_read_tool("host_profile",{})
    @mcp.tool()
    async def list_processes(filter: str|None=None, limit: int=200)->list: return await bridge.call_read_tool("list_processes",{"filter":filter,"limit":limit})
    @mcp.tool()
    async def inspect_process(pid: int)->dict: return await bridge.call_read_tool("inspect_process",{"pid":pid})
    @mcp.tool()
    async def list_listening_sockets()->list: return await bridge.call_read_tool("list_listening_sockets",{})
    @mcp.tool()
    async def list_connections(limit: int=500)->list: return await bridge.call_read_tool("list_connections",{"limit":limit})
    @mcp.tool()
    async def read_journal(since: str, unit: str|None=None, priority: str|None=None, limit: int=200)->dict: return await bridge.call_read_tool("read_journal",{"since":since,"unit":unit,"priority":priority,"limit":limit})
    @mcp.tool()
    async def read_log(path: str, lines: int=200)->dict: return await bridge.call_read_tool("read_log",{"path":path,"lines":lines})
    @mcp.tool()
    async def list_services(state: str|None=None)->dict: return await bridge.call_read_tool("list_services",{"state":state})
    @mcp.tool()
    async def service_status(unit: str)->dict: return await bridge.call_read_tool("service_status",{"unit":unit})
    @mcp.tool()
    async def list_users()->list: return await bridge.call_read_tool("list_users",{})
    @mcp.tool()
    async def get_metrics()->dict: return await bridge.call_read_tool("get_metrics",{})
    @mcp.tool()
    async def stop_process(pid: int, expected_start_time: str, approval_token: str="")->dict: return await bridge.call_mutable("stop_process",{"pid":pid,"expected_start_time":expected_start_time},approval_token)
    @mcp.tool()
    async def stop_service(unit: str, approval_token: str="")->dict: return await bridge.call_mutable("stop_service",{"unit":unit},approval_token)
    @mcp.tool()
    async def restart_service(unit: str, approval_token: str="")->dict: return await bridge.call_mutable("restart_service",{"unit":unit},approval_token)
    return mcp
