from __future__ import annotations

import hashlib


def parse_ps(text: str) -> list[dict]:
    records = []
    for line in text.splitlines():
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue
        try:
            pid, ppid, user, etimes = int(parts[0]), int(parts[1]), parts[2], int(parts[3])
        except ValueError:
            continue
        command = parts[4]; args = parts[5]
        records.append({"pid": pid, "ppid": ppid, "user": user, "elapsed_seconds": etimes,
                        "executable": command, "command": args, "suspicious_path": suspicious_path(args)})
    return records


def suspicious_path(command: str) -> bool:
    return any(token.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) for token in command.split()) or "(deleted)" in command


def process_fingerprint(process: dict) -> str:
    import re
    args = re.sub(r"\b(pid|port|nonce|token)[=:/-][^\s]+", lambda match: f"{match.group(1)}=<volatile>", process.get("command", ""), flags=re.I)
    raw = "\x1f".join((process.get("executable", ""), process.get("user", ""), args))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
