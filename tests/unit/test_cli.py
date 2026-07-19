import sys
from types import SimpleNamespace

import pytest

import screamsiem.cli as cli


def test_device_login_calls_codex_login_once(monkeypatch):
    calls = []
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/codex")
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda command, check: calls.append((command, check)) or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(sys, "argv", ["screamsiem", "auth", "login", "--device-auth"])

    with pytest.raises(SystemExit) as result:
        cli.main()

    assert result.value.code == 0
    assert calls == [(["codex", "login", "--device-auth"], False)]
