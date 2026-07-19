from __future__ import annotations
import argparse, asyncio, json
from .mcp_server import HostBridge, create_fastmcp_server
from ..config import settings
from ..ssh.asyncssh_transport import AsyncSSHTransport

def build_parser():
    p=argparse.ArgumentParser(description="Run one loopback ScreamSIEM host bridge")
    p.add_argument("--host-id",required=True); p.add_argument("--mcp-port",type=int,required=True); p.add_argument("--central-url",default="http://127.0.0.1:8080"); p.add_argument("--config-file",required=True); return p

async def run(args):
    with open(args.config_file) as fh: config=json.load(fh)
    transport=AsyncSSHTransport(config["address"],config["username"],config.get("port",22),config["identity_path"],config.get("known_hosts_path"),config.get("insecure",False))
    bridge=HostBridge(args.host_id,transport,args.mcp_port,approval_secret=settings.approval_secret,log_allowlist=config.get("log_files",[])); bridge.ensure_loopback()
    await bridge.start(); await bridge.start_collectors(await bridge.create_baseline())
    import uvicorn
    server=uvicorn.Server(uvicorn.Config(create_fastmcp_server(bridge).streamable_http_app(),host="127.0.0.1",port=args.mcp_port,log_level="info"))
    await server.serve()

def main(): asyncio.run(run(build_parser().parse_args()))
