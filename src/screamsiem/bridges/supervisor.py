from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from ..ssh.asyncssh_transport import AsyncSSHTransport
from .mcp_server import HostBridge
from .port_allocator import PortAllocator


class BridgeSupervisor:
    def __init__(self, settings, db, emit): self.settings,self.db,self.emit=settings,db,emit; self.ports=PortAllocator(settings.mcp_port_start,settings.mcp_port_end); self.bridges={}; self.processes={}
    async def start_host(self,host):
        port=host.bridge_port or self.ports.allocate(); self.ports.reserve(port) if port not in self.ports.allocated else None
        transport=AsyncSSHTransport(host.address,host.username,host.port,host.identity_path,host.known_hosts_path,"unsafe-ssh" in host.tags)
        bridge=HostBridge(host.id,transport,port,self.emit,self.settings.approval_secret,[]); self.bridges[host.id]=bridge
        await self.db.update_host(host.id,bridge_port=port,status="starting")
        try:
            await bridge.start(); baseline=await bridge.create_baseline(); await self.db.save_baseline(host.id,baseline); await bridge.start_collectors(baseline); self._spawn_bridge_process(host,port); await self.db.update_host(host.id,status="online",visibility="full")
        except Exception as exc: await self.db.update_host(host.id,status="offline",last_error=str(exc)); raise
        return bridge
    async def stop_host(self,host_id):
        bridge=self.bridges.pop(host_id,None)
        if bridge: await bridge.stop(); self.ports.release(bridge.port); await self.db.update_host(host_id,status="offline")
        process=self.processes.pop(host_id,None)
        if process and process.poll() is None: process.terminate()

    def _spawn_bridge_process(self, host, port):
        """Launch the host-local MCP boundary with no central secrets in its file."""
        bridge_dir=Path(self.settings.database).expanduser().parent/"bridges"; bridge_dir.mkdir(parents=True,exist_ok=True)
        config_path=bridge_dir/f"{host.id}.json"
        config={"address":host.address,"username":host.username,"port":host.port,"identity_path":host.identity_path,"known_hosts_path":host.known_hosts_path,"insecure":"unsafe-ssh" in host.tags,"log_files":[]}
        config_path.write_text(json.dumps(config)); os.chmod(config_path,0o600)
        command=[sys.executable,"-m","screamsiem.bridges.bridge_main","--host-id",host.id,"--mcp-port",str(port),"--central-url",self.settings.base_url or f"http://{self.settings.host}:{self.settings.port}","--config-file",str(config_path)]
        self.processes[host.id]=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

    async def stop_all(self):
        for host_id in list(self.bridges): await self.stop_host(host_id)
    async def get(self,host_id): return self.bridges.get(host_id)
