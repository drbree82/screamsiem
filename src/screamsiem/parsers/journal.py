from __future__ import annotations

import json


def parse_journal_line(line: str) -> dict | None:
    try: value=json.loads(line)
    except (json.JSONDecodeError, TypeError): return None
    if not isinstance(value, dict): return None
    return {"timestamp": value.get("__REALTIME_TIMESTAMP") or value.get("timestamp"), "unit": value.get("_SYSTEMD_UNIT"), "priority": value.get("PRIORITY"), "message": str(value.get("MESSAGE", ""))[:10000], "pid": value.get("_PID"), "uid": value.get("_UID"), "identifier": value.get("SYSLOG_IDENTIFIER"), "boot_id": value.get("_BOOT_ID")}
