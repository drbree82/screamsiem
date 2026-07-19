from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .approvals.service import ApprovalService
from .baselines.service import BaselineService
from .config import Settings, settings as default_settings
from .database import Database, new_id
from .detections.engine import DetectorEngine
from .investigator.gpt56 import GPTInvestigator
from .models import Action, Event, Finding, Host, HostCreate, MetricSample, TimelineEntry
from .ssh.asyncssh_transport import AsyncSSHTransport
from .bridges.mcp_server import HostBridge
from .bridges.supervisor import BridgeSupervisor

log=logging.getLogger("screamsiem")
TEMPLATES=Jinja2Templates(directory=str(Path(__file__).parent/"templates"))


class AppState:
    def __init__(self, config: Settings, db: Database, supervisor=None, investigator=None):
        self.settings,self.db=config,db; self.engine=DetectorEngine(); self.events: asyncio.Queue[dict]=asyncio.Queue(maxsize=2000); self.subscribers:set[asyncio.Queue]=set(); self.csrf=secrets.token_urlsafe(24); self.supervisor=supervisor; self.investigator=investigator or GPTInvestigator(model=config.openai_model,timeout=config.investigation_timeout_seconds,max_tool_calls=config.openai_max_tool_calls)
    async def publish(self, value):
        payload=value.model_dump(mode="json") if hasattr(value,"model_dump") else value
        queues=self.subscribers or {self.events}
        for queue in queues:
            try: queue.put_nowait(payload)
            except asyncio.QueueFull:
                try: queue.get_nowait(); queue.put_nowait(payload)
                except asyncio.QueueEmpty: pass
    async def ingest(self, item):
        if isinstance(item, MetricSample):
            await self.db.save_metric(item); await self.publish({"kind":"metric","data":item.model_dump(mode="json")}); await self.db.update_host(item.host_id,status="online",last_seen_at=item.observed_at); return None
        event=await self.db.upsert_event(item,self.settings.dedup_window_seconds); await self.publish({"kind":"event","data":event.model_dump(mode="json")})
        baseline=await self.db.get_baseline(event.host_id); findings=self.engine.evaluate(event,baseline)
        for finding in findings:
            finding=await self.db.upsert_finding(finding,event.id); await self.publish({"kind":"finding","data":finding.model_dump(mode="json")})
            if finding.severity=="critical": await self.db.update_host(finding.host_id,status="critical")
            if finding.severity in {"medium","high","critical"} and finding.state=="new": asyncio.create_task(self.investigate(finding))
        return findings
    async def investigate(self,finding: Finding):
        await self.db.upsert_finding(finding)
        events=await self.db.recent_events(finding.host_id,50); baseline=await self.db.get_baseline(finding.host_id) or {}; bridge=await self.supervisor.get(finding.host_id) if self.supervisor else None
        from .investigator.mcp_adapter import MCPReadOnlyAdapter
        try: result=await self.investigator.investigate(finding,baseline.get("profile",{}),events,MCPReadOnlyAdapter(bridge) if bridge else None,finding.ai_summary); await self.db.set_finding_ai(finding.id,result.model_dump(mode="json"),result.severity,result.confidence)
        except Exception as exc: log.exception("investigation failed"); result=None; await self.db.set_finding_ai(finding.id,{"error":"AI analysis unavailable","detail":str(exc)},finding.severity,finding.confidence)
        if result:
            for rec in result.recommended_actions:
                if rec.kind=="advisory": continue
                if rec.kind=="mcp_action" and rec.tool not in {"stop_process","stop_service","restart_service"}: continue
                action=Action(id=new_id("act"),finding_id=finding.id,host_id=finding.host_id,kind=rec.kind,label=rec.label,tool=rec.tool,arguments=rec.arguments,manual_command=rec.command,verification_command=rec.verification_command,impact=rec.impact,risk=rec.risk,created_at=datetime.now(timezone.utc))
                await self.db.add_action(action)
                await self.db.add_timeline(TimelineEntry(id=new_id("tl"),finding_id=finding.id,created_at=action.created_at,entry_type="action_proposed",actor="gpt-5.6",data={"action_id":action.id,"kind":action.kind,"tool":action.tool,"arguments":action.arguments,"label":action.label}))
        latest=await self.db.get_finding(finding.id); await self.publish({"kind":"finding","data":latest.model_dump(mode="json") if latest else finding.model_dump(mode="json")})


def create_app(config: Settings|None=None, db: Database|None=None, supervisor=None, investigator=None) -> FastAPI:
    config=config or default_settings; config.ensure_dirs(); database=db or Database(config.database); state=AppState(config,database,supervisor,investigator)
    if config.host not in {"127.0.0.1","localhost","::1"} and not config.allow_unauthenticated_remote:
        raise RuntimeError("refusing non-loopback bind without SCREAMSIEM_ALLOW_UNAUTHENTICATED_REMOTE=1")
    app=FastAPI(title="ScreamSIEM",version="0.1.0"); app.state.screamsiem=state; app.state.startup_database=database
    app.mount("/static",StaticFiles(directory=str(Path(__file__).parent/"static")),name="static")
    @app.on_event("startup")
    async def startup():
        await database.connect()
        if supervisor is None: state.supervisor=BridgeSupervisor(config,database,state.ingest)
        if investigator is None and config.openai_api_key:
            from openai import AsyncOpenAI
            state.investigator=GPTInvestigator(client=AsyncOpenAI(api_key=config.openai_api_key),model=config.openai_model,timeout=config.investigation_timeout_seconds,max_tool_calls=config.openai_max_tool_calls)
        async def restore_hosts():
            for host in await database.list_hosts():
                if host.id=="demo-host" or await state.supervisor.get(host.id): continue
                try: await state.supervisor.start_host(host)
                except Exception as exc: log.warning("host=%s restore failed: %s",host.name,exc)
        asyncio.create_task(restore_hosts())
        if os.getenv("SCREAMSIEM_DEMO") and not await database.get_host("demo-host"):
            demo=Host(id="demo-host",name="demo-linux",address="127.0.0.1",port=22,username="demo",identity_path="/tmp/demo-key",status="online",visibility="full",bridge_port=9100,created_at=datetime.now(timezone.utc))
            await database.add_host(demo)
            await database.save_baseline(demo.id,{"profile":{"hostname":"demo-linux","os_release":"ScreamSIEM deterministic demo","kernel":"demo-kernel"},"processes":[],"listeners":[],"services":[],"users":[],"capabilities":{"journal_readable":True}})
            from .ssh.fake_transport import FakeSSHTransport
            from .bridges.mcp_server import HostBridge
            fake=FakeSSHTransport({"stat":"8421 (python3) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 1234567 21\n","kill":""})
            state.supervisor.bridges[demo.id]=HostBridge(demo.id,fake,9100,state.ingest,config.approval_secret)
    @app.on_event("shutdown")
    async def shutdown():
        if state.supervisor and hasattr(state.supervisor,"stop_all"): await state.supervisor.stop_all()
        await database.close()

    @app.get("/",response_class=HTMLResponse)
    async def dashboard(request:Request): return TEMPLATES.TemplateResponse(request=request,name="dashboard.html",context={"csrf":state.csrf})
    @app.get("/healthz")
    async def healthz(): return {"status":"ok","version":"0.1.0"}
    @app.get("/readyz")
    async def readyz():
        if database.db is None: raise HTTPException(503,"database unavailable")
        return {"status":"ready"}
    @app.get("/api/hosts")
    async def hosts():
        result=[]
        for host in await database.list_hosts():
            value=host.model_dump(mode="json"); value["metrics"]=await database.latest_metrics(host.id); result.append(value)
        return result
    @app.post("/api/hosts")
    async def add_host(payload:HostCreate):
        if config.host not in {"127.0.0.1","localhost","::1"} and not config.allow_unauthenticated_remote: raise HTTPException(400,"remote binding requires SCREAMSIEM_ALLOW_UNAUTHENTICATED_REMOTE=1")
        if payload.insecure_skip_host_key_check: log.warning("host=%s unsafe SSH host-key checking enabled",payload.name)
        tags=list(payload.tags)+(["unsafe-ssh"] if payload.insecure_skip_host_key_check and "unsafe-ssh" not in payload.tags else [])
        host=Host(id=new_id("host"),name=payload.name,address=payload.address,port=payload.port,username=payload.username,identity_path=payload.identity_path,known_hosts_path=payload.known_hosts_path,tags=tags,status="provisioning",visibility="unknown",created_at=datetime.now(timezone.utc)); await database.add_host(host)
        try: await state.supervisor.start_host(host)
        except Exception as exc: await database.update_host(host.id,status="offline",last_error=str(exc))
        return (await database.get_host(host.id)).model_dump(mode="json")
    @app.get("/api/findings")
    async def findings():
        result=[]
        for f in await database.list_findings(True):
            value=f.model_dump(mode="json"); value["actions"]=[a.model_dump(mode="json") for a in await database.list_actions(f.id)]; result.append(value)
        return result
    @app.get("/findings/{finding_id}")
    async def finding_page(request:Request,finding_id:str):
        f=await database.get_finding(finding_id)
        if not f: raise HTTPException(404,"finding not found")
        return JSONResponse(await finding_payload(state,f))
    @app.get("/api/findings/{finding_id}")
    async def finding(finding_id:str):
        f=await database.get_finding(finding_id)
        if not f: raise HTTPException(404,"finding not found")
        return await finding_payload(state,f)
    @app.post("/api/findings/{finding_id}/investigate")
    async def investigate(finding_id:str):
        f=await database.get_finding(finding_id)
        if not f: raise HTTPException(404,"finding not found")
        await state.investigate(f); return await finding_payload(state,await database.get_finding(finding_id))
    @app.post("/api/findings/{finding_id}/dismiss")
    async def dismiss(finding_id:str,x_csrf_token:str|None=Header(default=None)):
        require_csrf(x_csrf_token,state); await database._c().execute("UPDATE findings SET state='dismissed',updated_at=? WHERE id=?",(datetime.now(timezone.utc).isoformat(),finding_id)); await database._c().commit(); return {"status":"dismissed"}
    @app.post("/api/actions/{action_id}/approve")
    async def approve(action_id:str,x_csrf_token:str|None=Header(default=None)):
        require_csrf(x_csrf_token,state)
        async def bridge_call(action,token):
            bridge=await state.supervisor.get(action.host_id) if state.supervisor else None
            if not bridge: return {"status":"error","error":"bridge unavailable"}
            return await bridge.call_mutable(action.tool or "",action.arguments,token)
        result=await ApprovalService(database,config.approval_secret,bridge_call).approve(action_id); return result.model_dump(mode="json")
    @app.post("/api/actions/{action_id}/reject")
    async def reject(action_id:str,x_csrf_token:str|None=Header(default=None)):
        require_csrf(x_csrf_token,state); return (await ApprovalService(database,config.approval_secret,lambda *_:None).reject(action_id)).model_dump(mode="json")
    @app.get("/api/stream")
    async def stream():
        queue:asyncio.Queue=asyncio.Queue(maxsize=500); state.subscribers.add(queue)
        async def generator():
            try:
                while True:
                    item=await queue.get(); yield f"data: {json.dumps(item,default=str)}\n\n"
            finally:
                state.subscribers.discard(queue)
        return StreamingResponse(generator(),media_type="text/event-stream",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})
    @app.post("/internal/events")
    async def internal_events(event:Event,request:Request,x_internal_secret:str|None=Header(default=None)):
        await require_internal(request,x_internal_secret,state); await state.ingest(event); return {"status":"accepted","event_id":event.id}
    @app.post("/internal/metrics")
    async def internal_metrics(metric:MetricSample,request:Request,x_internal_secret:str|None=Header(default=None)):
        await require_internal(request,x_internal_secret,state); await state.ingest(metric); return {"status":"accepted"}
    @app.post("/internal/hosts/{host_id}/heartbeat")
    async def heartbeat(host_id:str,request:Request,x_internal_secret:str|None=Header(default=None)):
        await require_internal(request,x_internal_secret,state); await database.update_host(host_id,status="online",last_seen_at=datetime.now(timezone.utc)); return {"status":"ok"}
    if os.getenv("SCREAMSIEM_DEMO"):
        @app.post("/api/demo/trigger")
        async def demo_trigger():
            from .events import make_event
            event=make_event("demo-host","socket","new_listening_socket","python3 /tmp/update.py began listening on 0.0.0.0:4444",{"address":"0.0.0.0","port":4444,"pid":8421,"process":"python3","command":"python3 /tmp/update.py","start_time":"1234567"},"critical"); await state.ingest(event); return {"event_id":event.id}
    return app


def require_csrf(token,state):
    if not token or not secrets.compare_digest(token,state.csrf): raise HTTPException(403,"CSRF token required")

async def require_internal(request,token,state):
    if token!=state.settings.internal_secret: raise HTTPException(403,"invalid internal token")
    if request.client and request.client.host not in {"127.0.0.1","::1","localhost"}: raise HTTPException(403,"internal route is loopback-only")

async def finding_payload(state,finding):
    actions=await state.db.list_actions(finding.id); timeline=await state.db.timeline(finding.id); return {"finding":finding.model_dump(mode="json"),"actions":[a.model_dump(mode="json") for a in actions],"timeline":[t.model_dump(mode="json") for t in timeline]}


app=create_app()
