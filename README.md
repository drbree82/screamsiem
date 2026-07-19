# ScreamSIEM

ScreamSIEM is a small AI-assisted Linux security monitor for a handful of hosts. It connects over SSH, builds a baseline from ordinary Unix interfaces, watches processes, sockets, services, journal/log streams and metrics, creates deterministic findings, and lets GPT-5.6 explain bounded evidence through local read-only MCP tools.

## Run the deterministic demo

```bash
python3 -m pip install -e .
./scripts/demo.sh
```

Open `http://127.0.0.1:8080/`. The demo creates a baseline, injects a suspicious `/tmp` listener event, produces a critical finding, and uses the deterministic investigator fallback when no API key is configured.

## Real SSH host

```bash
screamsiem host add --name web-01 --address 192.168.1.20 --user siem --identity ~/.ssh/id_ed25519
screamsiem serve
```

Each host is assigned a loopback-only MCP port in `9100-9199`; the supervisor launches a separate `bridge_main` process with a `0600` per-host config. The bridge keeps that host's SSH configuration, collectors and typed tools. GPT receives read-only tool schemas; mutation tools require a short-lived HMAC token created only after a human approves the exact action.

## Layout and verification

The named components are intentionally direct: `server`, `bridges`, `ssh`, `collectors`, `parsers`, `baselines`, `detections`, `investigator`, and `approvals`. Run `make test`; ordinary tests must not need SSH, root, or an OpenAI key.

GPT-5.6 integration is configurable with `OPENAI_API_KEY` and `OPENAI_MODEL`; Codex was used to implement and verify the bounded investigation, local MCP boundary, and approval flow described by the specification.

## Security boundaries

There is no generic shell MCP tool. Private keys and approval secrets never enter model input. Log/process content is untrusted evidence. Manual commands are display-only. See [SECURITY.md](SECURITY.md) for limitations and deployment warnings.
