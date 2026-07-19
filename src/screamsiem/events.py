from __future__ import annotations

import hashlib
import json

from .models import Event


def event_fingerprint(host_id: str, event_type: str, data: dict) -> str:
    canonical=json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(f"{host_id}\x1f{event_type}\x1f{canonical}".encode()).hexdigest()


def make_event(host_id: str, source: str, event_type: str, summary: str, data: dict,
               severity_hint: str = "medium", baseline_state: str = "unknown", raw_excerpt: str = "") -> Event:
    return Event(id="evt_" + hashlib.sha256((host_id + event_type + json.dumps(data, sort_keys=True)).encode()).hexdigest()[:24], host_id=host_id, source=source, event_type=event_type, severity_hint=severity_hint, fingerprint=event_fingerprint(host_id,event_type,data), summary=summary[:500], data=data, raw_excerpt=raw_excerpt[:10000], baseline_state=baseline_state)
