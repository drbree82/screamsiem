# ScreamSIEM

ScreamSIEM is a lightweight, AI-assisted Linux security monitor for small fleets. It connects to Linux hosts over SSH, learns a baseline from ordinary Unix interfaces, watches processes, sockets, services, journal/log streams and metrics, detects suspicious changes deterministically, and uses GPT-5.6 to investigate bounded evidence through local read-only MCP tools.

## Start here: three easy commands

Use the same long code in both commands. Replace `YOUR_CODE` with your own random code.

### 1. On every computer you want to watch

```bash
curl -fsSL https://screamsiem-installer.flrgx-cxz.workers.dev/monitored.sh \
  | sudo bash -s -- --enrollment-code 'YOUR_CODE'
```

### 2. On the computer that runs ScreamSIEM

```bash
curl -fsSL https://screamsiem-installer.flrgx-cxz.workers.dev/siem.sh \
  | sudo bash -s -- \
    --enrollment-code 'YOUR_CODE' \
    --install-dir /opt/screamsiem-controller \
    --cidr 192.168.68.0/24
```

Wait until the command says `enrolled 1 host(s)`.

During setup, the controller asks for your OpenAI API key. Type it into the hidden prompt and press Enter. This enables the live GPT-5.6 advisor. If you press Enter without a key, the monitor still works with its deterministic fallback investigator.

### 3. On your own computer, open the dashboard

```bash
ssh -N -L 8080:127.0.0.1:8080 YOUR_USERNAME@SIEM_IP
```

Keep that command running, then open [http://127.0.0.1:8080/](http://127.0.0.1:8080/) in your browser.

The setup commands need `sudo`. The dashboard tunnel uses your normal SSH username; you do not need to log in as root.

## Make the SIEM scream

On a monitored computer, run this safe demo command:

```bash
curl -fsSL https://screamsiem-installer.flrgx-cxz.workers.dev/demo.sh | bash
```

It starts a temporary HTTP listener on port `4444` for two minutes. ScreamSIEM should show a critical unexpected-listener finding within a few seconds. Stop it early with:

```bash
curl -fsSL https://screamsiem-installer.flrgx-cxz.workers.dev/demo.sh | bash -s -- --stop
```

When the listener disappears, the active finding resolves automatically while its event remains in incident history. New conditions create new active findings. With an API key configured, each finding shows `GPT-5.6 analysis`; the advisor reads current evidence through the host's read-only MCP tools and explains what it sees in plain English.

The dashboard distinguishes configuration from execution: `gpt-5.6 · live` means the last investigation succeeded, while `gpt-5.6 · fallback` means the API request failed and the safe deterministic advisor was used. Check `/api/status` and `journalctl -u screamsiem` for the redacted failure reason.

## Submission details

- Chosen track: Developer Tools
- Code: [github.com/drbree82/screamsiem](https://github.com/drbree82/screamsiem)
- Primary Codex build session: `019f7866-4331-7fa0-a233-5c2ac4eb6464`
- Demo video: add the public YouTube URL to `SUBMISSION.md` after publishing

The repository is MIT licensed. The deterministic demo is self-contained and does not need SSH access, root, or an OpenAI key.

## Quickstart

Requirements: Python 3.12+.

```bash
python3 -m pip install -e .
./scripts/demo.sh
```

Open [http://127.0.0.1:8080/](http://127.0.0.1:8080/). The demo creates a fake Linux host and baseline, injects a suspicious `/tmp` listener, creates a critical finding, runs the deterministic GPT-shaped fallback when no key is configured, and shows the approval/manual-action distinction.

To use GPT-5.6 for live investigations, set the key before starting the server:

```bash
export OPENAI_API_KEY="..."
export OPENAI_MODEL="gpt-5.6"
screamsiem serve
```

## Real SSH host

```bash
screamsiem host add \
  --name web-01 \
  --address 192.168.1.20 \
  --user siem \
  --identity ~/.ssh/id_ed25519
screamsiem serve
```

The server restores registered hosts, allocates a loopback MCP port in `9100-9199`, and launches a per-host bridge with a `0600` configuration. The bridge owns only that host's SSH connection and typed tools. Host-key verification is enabled by default; `--insecure-skip-host-key-check` is intentionally marked unsafe and is for disposable demos only.

## Curl-based fleet enrollment: details

For a hands-off LAN deployment, deploy the installer Worker described in [`cloudflare/installer-worker/README.md`](cloudflare/installer-worker/README.md), choose one high-entropy enrollment code, and use the same code for every host in that enrollment window.

On each monitored machine, run once as root:

```bash
curl -fsSL https://screamsiem-installer.flrgx-cxz.workers.dev/monitored.sh \
  | sudo bash -s -- --enrollment-code 'REPLACE_WITH_LONG_RANDOM_CODE'
```

On the SIEM machine, run once as root:

```bash
curl -fsSL https://screamsiem-installer.flrgx-cxz.workers.dev/siem.sh \
  | sudo bash -s -- --enrollment-code 'REPLACE_WITH_LONG_RANDOM_CODE'
```

The monitored bootstrap creates the dedicated `screamsiem` SSH account, registers bounded host metadata, and installs a short-lived systemd poller. The SIEM bootstrap generates its SSH keypair locally, publishes only the public key to the enrollment Worker, discovers enrolled addresses plus local ARP/mDNS/nmap candidates, verifies the host marker over SSH, imports the hosts, and starts the systemd service.

If `/opt/screamsiem` is already occupied by another checkout, add `--install-dir /opt/screamsiem-controller` to the SIEM command. The bootstrap never removes an existing non-ScreamSIEM directory.

No private key is uploaded to Cloudflare. The dashboard remains loopback-only; access it through an SSH tunnel unless you deliberately configure an authenticated reverse proxy.

## How to test

Run the full offline suite:

```bash
make test
```

The offline tests cover parsers, stable fingerprints, baseline-aware detectors, loopback bridge routing, bounded read tools, approval signatures, argument mismatch, expiry/replay protection, manual-command validation, the HTTP dashboard, deterministic finding creation, and approved fake remediation. Tests never require network access, root, an SSH server, or an OpenAI key.

The included sample data is generated at runtime by `scripts/demo.sh`; no external fixture download is needed. For a real SSH demo, `scripts/demo_attack.sh` prints the reversible command `python3 -m http.server 4444 --directory /tmp`.

## What judges should look for

1. Start the deterministic demo and open the dashboard.
2. Watch the green host state and live SSE connection.
3. Observe the full-width red critical banner for the unexpected listener and suspicious `/tmp` process.
4. Review the evidence, confidence, structured assessment, and action cards.
5. Approve the typed process-stop action; the exact action is signed, validated by the bridge, executed once, and written to the timeline.
6. Contrast it with the model-generated manual command, which is copy-only and never automatically executed.

## Architecture

The central FastAPI server owns SQLite persistence, baselines, deterministic detection, investigation orchestration, approvals, the dashboard and SSE. Each host has an SSH-native bridge with collectors and a loopback-only FastMCP boundary. GPT-5.6 sees bounded evidence and read-only function schemas; it never receives private keys, approval secrets, arbitrary shell access, or mutable tools during investigation.

The main components are deliberately explicit: `server`, `bridges`, `ssh`, `collectors`, `parsers`, `baselines`, `detections`, `investigator`, and `approvals`.

## How Codex and GPT-5.6 were used

Codex accelerated the workflow by turning the specification archive into a concrete implementation plan, scaffolding the Python package and SQLite model, writing the parser/detector/approval tests, iterating on the FastAPI/MCP integration, and repeatedly running the offline suite plus the loopback demo. Key implementation decisions were to keep detection deterministic, isolate each host behind a typed bridge, use fake SSH/GPT paths for reproducible tests, and require exact human approval before any mutation.

GPT-5.6 is the runtime investigator, not the detector or approver. It receives a bounded finding bundle, may request additional evidence through read-only MCP function calls, returns a validated structured assessment, and categorises recommendations as `mcp_action`, `manual_command`, or `advisory`. If the API is unavailable, the deterministic finding remains visible and the safe fallback explains that AI analysis is unavailable.

## Security and limitations

There is no generic shell MCP tool. Private keys and approval secrets never enter model input. Log/process content is treated as untrusted evidence. Mutation tokens bind the action ID, host, tool, exact canonical arguments, expiry and single-use nonce. Manual commands are display-only.

This is a Build Week MVP, not a production SOC. SQLite is not tamper-proof, a compromised host can lie to user-space collectors, polling can miss very short-lived events, and model-generated recommendations require human review. See [SECURITY.md](SECURITY.md).
