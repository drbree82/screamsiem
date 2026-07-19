import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from screamsiem.investigator.codex import CodexInvestigator
from screamsiem.models import Event, Finding


def make_finding() -> Finding:
    now = datetime.now(timezone.utc)
    return Finding(
        id="finding-1",
        host_id="host-1",
        detector_id="new_listener",
        correlation_key="listener:4444",
        severity="critical",
        confidence=0.9,
        title="Unexpected listener",
        machine_summary="python3 opened port 4444",
        first_seen_at=now,
        last_seen_at=now,
        updated_at=now,
        event_ids=["event-1"],
    )


@pytest.mark.asyncio
async def test_codex_exec_uses_headless_session_and_strict_output(monkeypatch):
    calls = []

    async def fake_process(args, input_text, cwd, env):
        calls.append((args, input_text, cwd, env))
        output = Path(args[args.index("--output-last-message") + 1])
        output.write_text(
            json.dumps(
                {
                    "title": "Unexpected listener",
                    "severity": "critical",
                    "confidence": 0.95,
                    "plain_english_summary": "A new listener appeared.",
                    "assessment": "Investigate the process.",
                    "observations": [{"text": "Port 4444 is open", "evidence_ids": ["event-1"]}],
                    "recommended_actions": [],
                }
            ),
            encoding="utf-8",
        )
        return 0, "", ""

    monkeypatch.setattr("screamsiem.investigator.codex.shutil.which", lambda _: "/usr/bin/codex")
    investigator = CodexInvestigator(process_runner=fake_process)
    result = await investigator.investigate(make_finding(), {"hostname": "demo"}, [])

    assert result.analysis_source == "gpt-5.6"
    args, prompt, _, env = calls[0]
    assert args[:4] == ["codex", "exec", "--ephemeral", "--skip-git-repo-check"]
    assert "--sandbox" in args and args[args.index("--sandbox") + 1] == "read-only"
    assert args[args.index("--model") + 1] == "gpt-5.6"
    assert "EVIDENCE_JSON:" in prompt
    assert "OPENAI_API_KEY" not in env


@pytest.mark.asyncio
async def test_codex_login_status_reports_chatgpt_session(monkeypatch):
    async def fake_process(args, input_text, cwd, env):
        assert args == ["codex", "login", "status"]
        return 0, "Logged in using ChatGPT\n", ""

    monkeypatch.setattr("screamsiem.investigator.codex.shutil.which", lambda _: "/usr/bin/codex")
    investigator = CodexInvestigator(process_runner=fake_process)
    assert await investigator.login_status() == {"available": True, "authenticated": True, "method": "chatgpt"}
