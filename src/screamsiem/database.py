from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sqlite3

from .models import Action, Event, Finding, Host, MetricSample, TimelineEntry


class _AsyncCursor:
    def __init__(self, cursor): self.cursor=cursor
    async def fetchone(self): return self.cursor.fetchone()
    async def fetchall(self): return self.cursor.fetchall()


class _AsyncConnection:
    """Async-shaped SQLite adapter that does not create worker threads.

    The MVP database operations are short and local. Keeping the awaitable
    repository API means aiosqlite can be substituted for larger deployments.
    """
    def __init__(self, path): self.conn=sqlite3.connect(path,check_same_thread=False); self.conn.row_factory=sqlite3.Row
    async def executescript(self, sql): self.conn.executescript(sql)
    async def execute(self, sql, params=()): return _AsyncCursor(self.conn.execute(sql,params))
    async def commit(self): self.conn.commit()
    async def close(self): self.conn.close()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat() if value else None


def dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL,
 username TEXT NOT NULL, identity_path TEXT NOT NULL, known_hosts_path TEXT, tags_json TEXT NOT NULL,
 status TEXT NOT NULL, visibility TEXT NOT NULL, bridge_port INTEGER, created_at TEXT NOT NULL,
 last_seen_at TEXT, last_error TEXT
);
CREATE TABLE IF NOT EXISTS baseline_versions (
 id TEXT PRIMARY KEY, host_id TEXT NOT NULL, version INTEGER NOT NULL, created_at TEXT NOT NULL,
 profile_json TEXT NOT NULL, process_fingerprints_json TEXT NOT NULL, listeners_json TEXT NOT NULL,
 services_json TEXT NOT NULL, users_json TEXT NOT NULL, capabilities_json TEXT NOT NULL, active INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY, host_id TEXT NOT NULL, observed_at TEXT NOT NULL, source TEXT NOT NULL,
 event_type TEXT NOT NULL, severity_hint TEXT NOT NULL, fingerprint TEXT NOT NULL, summary TEXT NOT NULL,
 data_json TEXT NOT NULL, raw_excerpt TEXT NOT NULL, baseline_state TEXT NOT NULL, first_seen_at TEXT NOT NULL,
 last_seen_at TEXT NOT NULL, occurrence_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_host_observed ON events(host_id, observed_at);
CREATE INDEX IF NOT EXISTS events_fingerprint ON events(host_id, fingerprint);
CREATE TABLE IF NOT EXISTS metric_samples (
 id TEXT PRIMARY KEY, host_id TEXT NOT NULL, observed_at TEXT NOT NULL, load_1 REAL NOT NULL,
 memory_used INTEGER NOT NULL, memory_total INTEGER NOT NULL, process_count INTEGER NOT NULL,
 tcp_connections INTEGER NOT NULL, listening_sockets INTEGER NOT NULL, collection_latency_ms REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, host_id TEXT NOT NULL, detector_id TEXT NOT NULL, correlation_key TEXT NOT NULL,
 state TEXT NOT NULL, severity TEXT NOT NULL, confidence REAL NOT NULL, title TEXT NOT NULL,
 machine_summary TEXT NOT NULL, ai_summary_json TEXT, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
 updated_at TEXT NOT NULL, occurrence_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_state ON findings(state);
CREATE TABLE IF NOT EXISTS finding_events (finding_id TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY(finding_id,event_id));
CREATE TABLE IF NOT EXISTS actions (
 id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, host_id TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL,
 tool TEXT, arguments_json TEXT NOT NULL, manual_command TEXT, verification_command TEXT, impact TEXT NOT NULL,
 risk TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, approved_at TEXT, executed_at TEXT, result_json TEXT
);
CREATE TABLE IF NOT EXISTS timeline_entries (
 id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, created_at TEXT NOT NULL, entry_type TEXT NOT NULL,
 actor TEXT NOT NULL, data_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS used_nonces (nonce TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
"""


class Database:
    def __init__(self, path: str):
        self.path = str(Path(path).expanduser())
        self.db: _AsyncConnection | None = None

    async def connect(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = _AsyncConnection(self.path)
        await self.db.executescript(SCHEMA)
        await self.db.commit()

    async def close(self) -> None:
        if self.db:
            await self.db.close()
            self.db = None

    def _c(self) -> _AsyncConnection:
        if not self.db:
            raise RuntimeError("database is not connected")
        return self.db

    async def add_host(self, host: Host) -> None:
        await self._c().execute("INSERT INTO hosts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            host.id, host.name, host.address, host.port, host.username, host.identity_path,
            host.known_hosts_path, json.dumps(host.tags), host.status, host.visibility, host.bridge_port,
            iso(host.created_at), iso(host.last_seen_at), host.last_error,
        ))
        await self._c().commit()

    async def update_host(self, host_id: str, **values: Any) -> None:
        if not values:
            return
        values = {k: (json.dumps(v) if k == "tags" else iso(v) if isinstance(v, datetime) else v) for k, v in values.items()}
        if "tags" in values:
            values["tags_json"] = values.pop("tags")
        clause = ", ".join(f"{k}=?" for k in values)
        await self._c().execute(f"UPDATE hosts SET {clause} WHERE id=?", (*values.values(), host_id))
        await self._c().commit()

    def _host(self, row: Any) -> Host:
        d = dict(row); d["tags"] = json.loads(d.pop("tags_json")); d.pop("known_hosts_path", None) if False else None
        return Host(**d)

    async def get_host(self, host_id: str) -> Host | None:
        cur = await self._c().execute("SELECT * FROM hosts WHERE id=?", (host_id,)); row = await cur.fetchone()
        return self._host(row) if row else None

    async def list_hosts(self) -> list[Host]:
        cur = await self._c().execute("SELECT * FROM hosts ORDER BY name"); return [self._host(r) for r in await cur.fetchall()]

    async def save_baseline(self, host_id: str, profile: dict[str, Any], version: int = 1) -> str:
        bid = new_id("base"); now = iso(datetime.now(timezone.utc))
        await self._c().execute("UPDATE baseline_versions SET active=0 WHERE host_id=?", (host_id,))
        await self._c().execute("INSERT INTO baseline_versions VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
            bid, host_id, version, now, json.dumps(profile.get("profile", {})), json.dumps(profile.get("processes", [])),
            json.dumps(profile.get("listeners", [])), json.dumps(profile.get("services", [])), json.dumps(profile.get("users", [])),
            json.dumps(profile.get("capabilities", {})), 1))
        await self._c().commit(); return bid

    async def get_baseline(self, host_id: str) -> dict[str, Any] | None:
        cur = await self._c().execute("SELECT * FROM baseline_versions WHERE host_id=? AND active=1 ORDER BY version DESC LIMIT 1", (host_id,)); r = await cur.fetchone()
        if not r: return None
        return {"id": r["id"], "version": r["version"], "profile": json.loads(r["profile_json"]), "processes": json.loads(r["process_fingerprints_json"]), "listeners": json.loads(r["listeners_json"]), "services": json.loads(r["services_json"]), "users": json.loads(r["users_json"]), "capabilities": json.loads(r["capabilities_json"])}

    async def upsert_event(self, event: Event, dedup_window_seconds: int = 300) -> Event:
        c = self._c(); cur = await c.execute("SELECT * FROM events WHERE host_id=? AND fingerprint=? ORDER BY last_seen_at DESC LIMIT 1", (event.host_id, event.fingerprint)); old = await cur.fetchone()
        now = event.observed_at
        if old and (now - dt(old["last_seen_at"])).total_seconds() <= dedup_window_seconds:
            await c.execute("UPDATE events SET last_seen_at=?, occurrence_count=occurrence_count+1, data_json=?, raw_excerpt=? WHERE id=?", (iso(now), json.dumps(event.data), event.raw_excerpt[:10000], old["id"]))
            await c.commit(); event.id = old["id"]; event.first_seen_at = dt(old["first_seen_at"]); event.last_seen_at = now; event.occurrence_count = old["occurrence_count"] + 1; return event
        event.first_seen_at = event.last_seen_at = now
        await c.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (event.id,event.host_id,iso(event.observed_at),event.source,event.event_type,event.severity_hint,event.fingerprint,event.summary,json.dumps(event.data),event.raw_excerpt[:10000],event.baseline_state,iso(now),iso(now),event.occurrence_count))
        await c.commit(); return event

    def _event(self, r: Any) -> Event:
        d=dict(r); d["data"]=json.loads(d.pop("data_json")); d["first_seen_at"]=dt(d.pop("first_seen_at")); d["last_seen_at"]=dt(d.pop("last_seen_at")); d.pop("occurrence_count", None) if False else None; return Event(**d)

    async def recent_events(self, host_id: str, limit: int = 100) -> list[Event]:
        cur=await self._c().execute("SELECT * FROM events WHERE host_id=? ORDER BY observed_at DESC LIMIT ?",(host_id,limit)); return [self._event(r) for r in await cur.fetchall()]

    async def save_metric(self, m: MetricSample) -> None:
        await self._c().execute("INSERT INTO metric_samples VALUES (?,?,?,?,?,?,?,?,?,?)", (new_id("met"),m.host_id,iso(m.observed_at),m.load_1,m.memory_used,m.memory_total,m.process_count,m.tcp_connections,m.listening_sockets,m.collection_latency_ms)); await self._c().commit()

    async def latest_metrics(self, host_id: str) -> dict[str, Any] | None:
        cur=await self._c().execute("SELECT * FROM metric_samples WHERE host_id=? ORDER BY observed_at DESC LIMIT 1",(host_id,)); r=await cur.fetchone(); return dict(r) if r else None

    async def upsert_finding(self, finding: Finding, event_id: str | None = None) -> Finding:
        c=self._c(); cur=await c.execute("SELECT * FROM findings WHERE host_id=? AND correlation_key=? AND state NOT IN ('resolved','dismissed')",(finding.host_id,finding.correlation_key)); old=await cur.fetchone()
        if old:
            finding.id=old["id"]; finding.first_seen_at=dt(old["first_seen_at"]) or finding.first_seen_at; finding.count=old["occurrence_count"]+1
            await c.execute("UPDATE findings SET severity=?,last_seen_at=?,updated_at=?,occurrence_count=? WHERE id=?",(finding.severity,iso(finding.last_seen_at),iso(finding.updated_at),finding.count,finding.id))
        else:
            await c.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(finding.id,finding.host_id,finding.detector_id,finding.correlation_key,finding.state,finding.severity,finding.confidence,finding.title,finding.machine_summary,json.dumps(finding.ai_summary) if finding.ai_summary else None,iso(finding.first_seen_at),iso(finding.last_seen_at),iso(finding.updated_at),finding.count))
        if event_id: await c.execute("INSERT OR IGNORE INTO finding_events VALUES (?,?)",(finding.id,event_id))
        await c.commit(); return finding

    def _finding(self,r:Any)->Finding:
        d=dict(r); d["ai_summary"]=json.loads(d.pop("ai_summary_json")) if d.get("ai_summary_json") else None; d["first_seen_at"]=dt(d["first_seen_at"]); d["last_seen_at"]=dt(d["last_seen_at"]); d["updated_at"]=dt(d["updated_at"]); d["count"]=d.pop("occurrence_count"); return Finding(**d)

    async def get_finding(self, finding_id: str) -> Finding | None:
        cur=await self._c().execute("SELECT * FROM findings WHERE id=?",(finding_id,)); r=await cur.fetchone(); return self._finding(r) if r else None

    async def list_findings(self, active_only: bool = False) -> list[Finding]:
        q="SELECT * FROM findings" + (" WHERE state NOT IN ('resolved','dismissed')" if active_only else "") + " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, updated_at DESC"; cur=await self._c().execute(q); return [self._finding(r) for r in await cur.fetchall()]

    async def set_finding_ai(self, finding_id: str, investigation: dict[str, Any], severity: str, confidence: float) -> None:
        await self._c().execute("UPDATE findings SET ai_summary_json=?,severity=?,confidence=?,state='open',updated_at=? WHERE id=?",(json.dumps(investigation),severity,confidence,iso(datetime.now(timezone.utc)),finding_id)); await self._c().commit()

    async def add_action(self, a: Action) -> None:
        await self._c().execute("INSERT INTO actions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(a.id,a.finding_id,a.host_id,a.kind,a.label,a.tool,json.dumps(a.arguments),a.manual_command,a.verification_command,a.impact,a.risk,a.state,iso(a.created_at),iso(a.approved_at),iso(a.executed_at),json.dumps(a.result) if a.result else None)); await self._c().commit()

    def _action(self,r:Any)->Action:
        d=dict(r); d["arguments"]=json.loads(d.pop("arguments_json")); d["result"]=json.loads(d.pop("result_json")) if d.get("result_json") else None; d["created_at"]=dt(d["created_at"]); d["approved_at"]=dt(d["approved_at"]); d["executed_at"]=dt(d["executed_at"]); return Action(**d)

    async def get_action(self, action_id: str)->Action|None:
        cur=await self._c().execute("SELECT * FROM actions WHERE id=?",(action_id,)); r=await cur.fetchone(); return self._action(r) if r else None

    async def list_actions(self, finding_id: str|None=None)->list[Action]:
        cur=await self._c().execute("SELECT * FROM actions" + (" WHERE finding_id=?" if finding_id else "") + " ORDER BY created_at",(finding_id,) if finding_id else ()); return [self._action(r) for r in await cur.fetchall()]

    async def update_action(self, action_id: str, **values: Any)->None:
        values={k:(json.dumps(v) if k in {"result","arguments"} else iso(v) if isinstance(v,datetime) else v) for k,v in values.items()}
        if "result" in values: values["result_json"]=values.pop("result")
        if "arguments" in values: values["arguments_json"]=values.pop("arguments")
        clause=", ".join(f"{k}=?" for k in values); await self._c().execute(f"UPDATE actions SET {clause} WHERE id=?",(*values.values(),action_id)); await self._c().commit()

    async def add_timeline(self, entry: TimelineEntry)->None:
        await self._c().execute("INSERT INTO timeline_entries VALUES (?,?,?,?,?,?)",(entry.id,entry.finding_id,iso(entry.created_at),entry.entry_type,entry.actor,json.dumps(entry.data))); await self._c().commit()

    async def timeline(self, finding_id: str)->list[TimelineEntry]:
        cur=await self._c().execute("SELECT * FROM timeline_entries WHERE finding_id=? ORDER BY created_at",(finding_id,)); out=[]
        for r in await cur.fetchall():
            d=dict(r); d["created_at"]=dt(d["created_at"]); d["data"]=json.loads(d.pop("data_json")); out.append(TimelineEntry(**d))
        return out

    async def mark_nonce(self, nonce: str, expires_at: datetime)->bool:
        try:
            await self._c().execute("INSERT INTO used_nonces VALUES (?,?)",(nonce,iso(expires_at))); await self._c().commit(); return True
        except Exception: return False
