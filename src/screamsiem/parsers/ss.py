from __future__ import annotations

import re


def _endpoint(value: str) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("[") and "]" in value:
        host, port = value[1:].split("]", 1); return host, int(port.lstrip(":") or 0)
    if value.count(":") > 1:
        host, _, port = value.rpartition(":"); return host, int(port or 0)
    host, _, port = value.rpartition(":"); return host, int(port or 0)


def parse_ss(text: str, listening: bool | None = None) -> list[dict]:
    out = []
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith(("Netid", "State")): continue
        parts=line.split()
        if len(parts)<5: continue
        if parts[0].lower() in {"tcp","tcp6","udp","udp6","unix"}:
            protocol, state, local, peer = parts[0], parts[1], parts[4], parts[5] if len(parts)>5 else ""
            user_start = 6
        else:
            protocol, state, local, peer = "tcp", parts[0], parts[3], parts[4] if len(parts)>4 else ""
            user_start = 5
        if listening is True and state.upper() not in {"LISTEN", "UNCONN"}: continue
        try: address, port = _endpoint(local)
        except (ValueError, IndexError): continue
        record={"protocol": protocol, "state": state, "local_address": address, "port": port, "peer": peer, "raw": line}
        users = " ".join(parts[user_start:])
        match=re.search(r"users:\(\(\"([^\"]+)", users)
        if match: record["process"] = match.group(1)
        pid=re.search(r"pid=(\d+)", users)
        if pid: record["pid"] = int(pid.group(1))
        out.append(record)
    return out
