from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CommandResult(BaseModel):
    stdout: str = ""
    stderr: str = ""
    exit_status: int = 0
    duration_ms: float = 0
    timed_out: bool = False


class HostCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    address: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=1, max_length=128)
    port: int = Field(default=22, ge=1, le=65535)
    identity_path: str = Field(min_length=1, max_length=1024)
    known_hosts_path: str | None = None
    tags: list[str] = Field(default_factory=list)
    log_files: list[str] = Field(default_factory=list)
    insecure_skip_host_key_check: bool = False


class Host(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    address: str
    port: int
    username: str
    identity_path: str
    known_hosts_path: str | None = None
    tags: list[str] = Field(default_factory=list)
    status: str = "offline"
    visibility: str = "unknown"
    bridge_port: int | None = None
    created_at: datetime
    last_seen_at: datetime | None = None
    last_error: str | None = None


class Event(BaseModel):
    id: str
    host_id: str
    observed_at: datetime = Field(default_factory=utcnow)
    source: str
    event_type: str
    severity_hint: Literal["low", "medium", "high", "critical"] = "low"
    fingerprint: str
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    raw_excerpt: str = ""
    baseline_state: str = "unknown"
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    occurrence_count: int = 1


class MetricSample(BaseModel):
    host_id: str
    observed_at: datetime = Field(default_factory=utcnow)
    load_1: float = 0
    memory_used: int = 0
    memory_total: int = 0
    process_count: int = 0
    tcp_connections: int = 0
    listening_sockets: int = 0
    collection_latency_ms: float = 0
    event_rate: float = 0
    uptime_seconds: float = 0


class Finding(BaseModel):
    id: str
    host_id: str
    detector_id: str
    correlation_key: str
    state: str = "new"
    severity: str = "medium"
    confidence: float = 0.5
    title: str
    machine_summary: str
    ai_summary: dict[str, Any] | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    updated_at: datetime
    count: int = 1
    event_ids: list[str] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    kind: Literal["mcp_action", "manual_command", "advisory"]
    label: str
    tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    command: str | None = None
    verification_command: str | None = None
    impact: str = ""
    risk: str = "medium"

    @field_validator("command")
    @classmethod
    def one_line_command(cls, value: str | None) -> str | None:
        if value is not None and ("\n" in value or "\r" in value):
            raise ValueError("manual commands must be one line")
        return value

    @model_validator(mode="after")
    def validate_action(self):
        if self.kind == "mcp_action" and (not self.tool or self.command):
            raise ValueError("mcp_action requires a tool and has no executable command")
        if self.kind == "manual_command":
            if not self.command:
                raise ValueError("manual_command requires a command")
            lowered=self.command.lower()
            forbidden=("curl |", "curl|", "wget |", "wget|", "| bash", "| sh", "`", "$(", ";;")
            if any(token in lowered for token in forbidden):
                raise ValueError("manual command contains a forbidden execution pattern")
        return self


class Investigation(BaseModel):
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    plain_english_summary: str
    observations: list[dict[str, Any]] = Field(default_factory=list)
    assessment: str
    alternative_explanations: list[str] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    next_evidence_to_collect: list[str] = Field(default_factory=list)
    analysis_source: Literal["gpt-5.6", "fallback"] = "fallback"


class Action(BaseModel):
    id: str
    finding_id: str
    host_id: str
    kind: str
    label: str
    tool: str | None
    arguments: dict[str, Any] = Field(default_factory=dict)
    manual_command: str | None = None
    verification_command: str | None = None
    impact: str = ""
    risk: str = "medium"
    state: str = "pending"
    created_at: datetime
    approved_at: datetime | None = None
    executed_at: datetime | None = None
    result: dict[str, Any] | None = None


class TimelineEntry(BaseModel):
    id: str
    finding_id: str
    created_at: datetime
    entry_type: str
    actor: str
    data: dict[str, Any] = Field(default_factory=dict)
