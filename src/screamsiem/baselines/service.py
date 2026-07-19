from __future__ import annotations

from ..parsers.passwd import parse_passwd
from ..parsers.ps import parse_ps, process_fingerprint
from ..parsers.ss import parse_ss


class BaselineService:
    def __init__(self, transport): self.transport=transport

    async def profile(self) -> dict:
        commands={
            "hostname": ["hostname"], "os_release": ["cat","/etc/os-release"], "kernel": ["uname","-a"], "uptime": ["uptime"],
            "processes": ["ps","-eo","pid,ppid,user,etimes,comm,args","--no-headers"], "listeners": ["ss","-Hltunp"],
            "connections": ["ss","-Htuna"], "services": ["systemctl","list-units","--type=service","--all","--no-legend","--no-pager"],
            "users": ["getent","passwd"],
        }
        results={k: await self.transport.run(v) for k,v in commands.items()}
        processes=parse_ps(results["processes"].stdout); listeners=parse_ss(results["listeners"].stdout, listening=True); users=parse_passwd(results["users"].stdout)
        services=[{"unit":x.split()[0],"state":x.split()[3] if len(x.split())>3 else "unknown","raw":x[:500]} for x in results["services"].stdout.splitlines() if x.strip()]
        capabilities={"journal_readable":(await self.transport.run(["journalctl","-n","1","--no-pager"])).exit_status==0,"auth_log_readable":False,"process_owner_visibility":"full","socket_process_visibility":"full","sudo_available":False}
        return {"profile":{"hostname":results["hostname"].stdout.strip(),"os_release":results["os_release"].stdout[:5000],"kernel":results["kernel"].stdout.strip(),"uptime":results["uptime"].stdout.strip(),"current_user":(await self.transport.run(["id","-un"])).stdout.strip(),"baseline_timestamp":__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()},"processes":[{**p,"fingerprint":process_fingerprint(p)} for p in processes],"listeners":listeners,"services":services,"users":users,"capabilities":capabilities}
