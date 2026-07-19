# ScreamSIEM submission checklist

Fill in the YouTube URL after publishing the public video.

- Track: **Developer Tools**
- Repository: <https://github.com/drbree82/screamsiem>
- Demo video: **TODO — public YouTube URL**
- Primary Codex Session ID: `019f7866-4331-7fa0-a233-5c2ac4eb6464`
- License: MIT

## Text description

ScreamSIEM is an AI-native Linux security monitor for people who do not need an enterprise SOC. It connects to ordinary servers over SSH, builds a baseline from Unix-native telemetry, continuously watches logs, processes, services and network state, and uses GPT-5.6 to investigate suspicious changes. GPT-5.6 explains what it sees, gathers additional evidence through local read-only MCP tools, offers approval-gated fixes when a typed tool exists, and gives the sysadmin a reviewable Bash one-liner when it does not. The model can investigate the fleet, but it cannot silently give itself root.

## Three-minute video outline

Keep the finished public YouTube video at or under three minutes and include English voiceover.

| Time | Show and say |
|---|---|
| 0:00–0:25 | Problem and pitch: small Linux fleets need useful security visibility without an enterprise SIEM. |
| 0:25–0:55 | Start `./scripts/demo.sh`; show the healthy host card, baseline, metrics and live SSE state. |
| 0:55–1:25 | Trigger the suspicious `/tmp` listener; show the red critical banner, deterministic detector, evidence and confidence. |
| 1:25–1:55 | Explain GPT-5.6: it receives bounded evidence, can call read-only MCP tools, and returns a validated assessment. |
| 1:55–2:25 | Explain Codex: it scaffolded the components from the spec, added fake SSH/GPT tests, and iterated until the offline suite and demo passed. |
| 2:25–2:50 | Approve the exact typed action; show the result and timeline. Contrast the copy-only manual command. |
| 2:50–3:00 | State the repository URL, chosen track and the safety boundary: no arbitrary shell and no automatic remediation. |
