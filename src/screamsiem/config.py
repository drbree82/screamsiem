from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8080
    database: str = "./data/screamsiem.db"
    mcp_port_start: int = 9100
    mcp_port_end: int = 9199
    internal_secret: str = ""
    approval_secret: str = ""
    log_level: str = "INFO"
    base_url: str = ""
    trust_proxy: bool = False
    allow_unauthenticated_remote: bool = False
    ai_provider: str = "api"
    openai_api_key: str = ""
    openai_model: str = "gpt-5.6"
    codex_command: str = "codex"
    codex_model: str = "gpt-5.6-sol"
    openai_reasoning_effort: str = "medium"
    openai_max_tool_calls: int = 8
    investigation_timeout_seconds: int = 60
    process_poll_seconds: float = 5.0
    socket_poll_seconds: float = 5.0
    service_poll_seconds: float = 30.0
    metric_poll_seconds: float = 2.0
    dedup_window_seconds: int = 300

    @classmethod
    def from_env(cls) -> "Settings":
        defaults = cls()
        return cls(
            host=os.getenv("SCREAMSIEM_HOST", defaults.host),
            port=int(os.getenv("SCREAMSIEM_PORT", defaults.port)),
            database=os.getenv("SCREAMSIEM_DATABASE", defaults.database),
            mcp_port_start=int(os.getenv("SCREAMSIEM_MCP_PORT_START", defaults.mcp_port_start)),
            mcp_port_end=int(os.getenv("SCREAMSIEM_MCP_PORT_END", defaults.mcp_port_end)),
            internal_secret=os.getenv("SCREAMSIEM_INTERNAL_SECRET", secrets.token_urlsafe(32)),
            approval_secret=os.getenv("SCREAMSIEM_APPROVAL_SECRET", secrets.token_urlsafe(32)),
            log_level=os.getenv("SCREAMSIEM_LOG_LEVEL", defaults.log_level),
            base_url=os.getenv("SCREAMSIEM_BASE_URL", defaults.base_url),
            trust_proxy=_bool("SCREAMSIEM_TRUST_PROXY"),
            allow_unauthenticated_remote=_bool("SCREAMSIEM_ALLOW_UNAUTHENTICATED_REMOTE"),
            ai_provider=os.getenv("SCREAMSIEM_AI_PROVIDER", defaults.ai_provider).lower(),
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            openai_model=os.getenv("OPENAI_MODEL", defaults.openai_model),
            codex_command=os.getenv("SCREAMSIEM_CODEX_COMMAND", defaults.codex_command),
            codex_model=os.getenv("CODEX_MODEL", defaults.codex_model),
            openai_reasoning_effort=os.getenv("OPENAI_REASONING_EFFORT", defaults.openai_reasoning_effort),
            openai_max_tool_calls=int(os.getenv("OPENAI_MAX_TOOL_CALLS", defaults.openai_max_tool_calls)),
            investigation_timeout_seconds=int(os.getenv("OPENAI_INVESTIGATION_TIMEOUT_SECONDS", defaults.investigation_timeout_seconds)),
        )

    def ensure_dirs(self) -> None:
        Path(self.database).expanduser().parent.mkdir(parents=True, exist_ok=True)


settings = Settings.from_env()
