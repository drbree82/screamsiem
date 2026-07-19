from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Awaitable, Callable

from ..models import Event, Finding, Investigation
from .gpt56 import GPTInvestigator
from .prompts import SYSTEM_PROMPT

log = logging.getLogger("screamsiem.ai.codex")

ProcessRunner = Callable[[list[str], str, str, dict[str, str]], Awaitable[tuple[int, str, str]]]


class CodexInvestigator(GPTInvestigator):
    """Run the investigator through a locally authenticated Codex CLI session.

    Codex CLI owns the ChatGPT browser login and its refreshable credentials. The
    application only sends bounded evidence to ``codex exec`` and reads the
    structured final message; it never reads or stores the Codex auth file.
    """

    mode = "codex"

    def __init__(
        self,
        command: str = "codex",
        model: str = "gpt-5.6-sol",
        timeout: int = 60,
        max_tool_calls: int = 8,
        process_runner: ProcessRunner | None = None,
    ):
        super().__init__(client=None, model=model, timeout=timeout, max_tool_calls=max_tool_calls)
        self.command = command
        self.process_runner = process_runner
        self.authenticated: bool | None = None
        self.auth_method: str | None = None

    @property
    def available(self) -> bool:
        return bool(shutil.which(self.command))

    async def login_status(self) -> dict[str, Any]:
        if not self.available:
            self.authenticated = False
            self.auth_method = None
            return {"available": False, "authenticated": False, "method": None}
        try:
            code, stdout, stderr = await self._process([self.command, "login", "status"], "", os.getcwd(), os.environ.copy())
        except Exception as exc:
            self.authenticated = False
            self.auth_method = None
            return {"available": True, "authenticated": False, "method": None, "error": self._safe_error(exc)}
        text = f"{stdout}\n{stderr}".strip()
        authenticated = code == 0 and "not logged" not in text.lower() and "logged out" not in text.lower()
        lowered = text.lower()
        method = "chatgpt" if "chatgpt" in lowered else "api_key" if "api key" in lowered else "unknown"
        self.authenticated = authenticated
        self.auth_method = method if authenticated else None
        return {"available": True, "authenticated": authenticated, "method": self.auth_method}

    async def investigate(self, finding: Finding, host_profile: dict, events: list[Event], tool_adapter=None, previous: dict | None = None) -> Investigation:
        self.calls += 1
        evidence = {
            "finding": finding.model_dump(mode="json"),
            "host_profile": host_profile,
            "events": [event.model_dump(mode="json") for event in events[-50:]],
            "previous": previous,
            "mutable_capabilities": ["stop_process", "stop_service", "restart_service"],
        }
        if not self.available:
            self.fallbacks += 1
            self.last_result = "fallback"
            self.last_error = f"Codex CLI not found: {self.command}"
            return self.fallback(finding, events)
        try:
            response = await asyncio.wait_for(self._run(evidence), self.timeout)
            result = self._parse(response)
            result.analysis_source = "gpt-5.6"
            self.successes += 1
            self.last_result = "live"
            self.last_error = None
            return result
        except Exception as exc:
            self.fallbacks += 1
            self.last_result = "fallback"
            self.last_error = self._safe_error(exc)
            log.warning("Codex GPT-5.6 investigation failed: %s", self.last_error)
            return self.fallback(finding, events)

    async def _run(self, evidence: dict[str, Any]) -> str:
        with tempfile.TemporaryDirectory(prefix="screamsiem-codex-") as workdir:
            schema_path = Path(workdir) / "investigation.schema.json"
            output_path = Path(workdir) / "investigation.json"
            schema_path.write_text(json.dumps(Investigation.model_json_schema()), encoding="utf-8")
            prompt = (
                f"{SYSTEM_PROMPT}\n\n"
                "You are being called by ScreamSIEM through Codex exec. Analyze only the JSON evidence below. "
                "Do not inspect files, run commands, use network access, or invent tool results. "
                "Return only the requested JSON object.\n\n"
                f"EVIDENCE_JSON:\n{json.dumps({'format': 'json', 'evidence': evidence}, separators=(',', ':'))}"
            )
            args = [
                self.command,
                "exec",
                "--ephemeral",
                "--skip-git-repo-check",
                "--sandbox",
                "read-only",
                "--color",
                "never",
                "--model",
                self.model,
                "--output-schema",
                str(schema_path),
                "--output-last-message",
                str(output_path),
                "-C",
                workdir,
                "-",
            ]
            env = os.environ.copy()
            # An explicit Codex provider must use the ChatGPT session, not an
            # accidentally inherited API key.
            env.pop("OPENAI_API_KEY", None)
            code, stdout, stderr = await self._process(args, prompt, workdir, env)
            if code != 0:
                detail = (stderr or stdout or "Codex exec failed").strip()
                raise RuntimeError(detail[:500])
            if output_path.is_file():
                return output_path.read_text(encoding="utf-8")
            return stdout

    async def _process(self, args: list[str], input_text: str, cwd: str, env: dict[str, str]) -> tuple[int, str, str]:
        if self.process_runner:
            return await self.process_runner(args, input_text, cwd, env)
        process = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(input_text.encode()), self.timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise TimeoutError("Codex exec timed out")
        return process.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    def _parse(self, value: Any) -> Investigation:
        if isinstance(value, dict):
            return Investigation.model_validate(value)
        text = str(value).strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE | re.DOTALL).strip()
        try:
            return Investigation.model_validate_json(text)
        except Exception:
            start, end = text.find("{"), text.rfind("}")
            if start < 0 or end <= start:
                raise
            return Investigation.model_validate_json(text[start : end + 1])
