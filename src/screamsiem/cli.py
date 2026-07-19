from __future__ import annotations
import argparse, asyncio, json, os, shutil, subprocess
from datetime import datetime, timezone
from .config import settings
from .database import Database, new_id
from .models import Host

def parser():
    p=argparse.ArgumentParser(prog="screamsiem"); sub=p.add_subparsers(dest="command",required=True)
    host=sub.add_parser("host"); hs=host.add_subparsers(dest="host_command",required=True); add=hs.add_parser("add")
    add.add_argument("--name",required=True); add.add_argument("--address",required=True); add.add_argument("--user",required=True,dest="username"); add.add_argument("--identity",required=True,dest="identity_path"); add.add_argument("--port",type=int,default=22); add.add_argument("--known-hosts",dest="known_hosts_path"); add.add_argument("--tags",default=""); add.add_argument("--log-file",action="append",default=[]); add.add_argument("--insecure-skip-host-key-check",action="store_true")
    sub.add_parser("serve")
    auth=sub.add_parser("auth"); ah=auth.add_subparsers(dest="auth_command",required=True)
    login=ah.add_parser("login"); login.add_argument("--device-auth",action="store_true",help="print a browser URL and device code for headless servers")
    ah.add_parser("status")
    return p

async def add_host(args):
    db=Database(settings.database); await db.connect();
    for existing in await db.list_hosts():
        if existing.name == args.name or existing.address == args.address:
            print(json.dumps(existing.model_dump(mode="json"),indent=2)); await db.close(); return
    tags=[x for x in args.tags.split(",") if x]+(["unsafe-ssh"] if args.insecure_skip_host_key_check else []); host=Host(id=new_id("host"),name=args.name,address=args.address,port=args.port,username=args.username,identity_path=os.path.expanduser(args.identity_path),known_hosts_path=args.known_hosts_path,tags=tags,status="pending",visibility="unknown",created_at=datetime.now(timezone.utc)); await db.add_host(host); print(json.dumps(host.model_dump(mode="json"),indent=2)); await db.close()

def main():
    args=parser().parse_args()
    if args.command=="host" and args.host_command=="add": asyncio.run(add_host(args))
    elif args.command=="auth":
        if not shutil.which(settings.codex_command):
            raise SystemExit(f"Codex CLI not found: {settings.codex_command}. Install @openai/codex first.")
        command=[settings.codex_command,"login"]
        if args.auth_command == "status":
            command.append("status")
        if args.auth_command == "login" and args.device_auth:
            command.append("--device-auth")
            print("Copy the URL and device code printed below into a browser on another computer.", flush=True)
        result=subprocess.run(command,check=False)
        raise SystemExit(result.returncode)
    elif args.command=="serve":
        import uvicorn
        uvicorn.run("screamsiem.server:app",host=settings.host,port=settings.port)
