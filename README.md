# ScreamSIEM

ScreamSIEM is a lightweight, AI-assisted Linux security monitor for small fleets. It connects to Linux hosts over SSH, learns a baseline from ordinary Unix interfaces, watches processes, sockets, services, journal/log streams and metrics, detects suspicious changes deterministically, and uses GPT-5.6 to investigate bounded evidence through local read-only MCP tools.

## Start here: install the fleet monitor

The installer runs on the SIEM/controller machine as root. It creates the `screamsiem` service account, installs the Python application and Codex CLI when needed, enrolls monitored hosts, and starts a loopback-only systemd service. The monitored-host script runs once on each Linux host.

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

During setup, choose `codex` to use a ChatGPT subscription through Codex. The headless installer prints a one-time device-auth URL and code; open that URL on any computer, sign in with ChatGPT, and enter the code. No API key is stored. Choose `api` for usage-based API-key access, or `fallback` for deterministic-only operation.

For a non-interactive provider choice, set it through `sudo env` so it reaches the installer running as root:

```bash
curl -fsSL https://screamsiem-installer.flrgx-cxz.workers.dev/siem.sh \
  | sudo env SCREAMSIEM_AI_PROVIDER=codex bash -s -- \
    --enrollment-code 'YOUR_CODE' \
    --install-dir /opt/screamsiem-controller \
    --cidr 192.168.68.0/24
```

When `codex` is selected, the server prints a URL and device code. Copy both into a browser on another computer, complete ChatGPT sign-in, and leave the installer terminal open until it confirms login and finishes. The credentials are kept in the service account's private `CODEX_HOME`; ScreamSIEM does not read or copy them.

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

When the listener disappears, the active finding resolves automatically while its event remains in incident history. New conditions create new active findings. A successful API-key investigation is shown as `gpt-5.6 · live`; a successful Codex investigation is shown as `gpt-5.6-sol · live`. API-key mode can request current evidence through the host's read-only MCP tools. Codex mode sends the bounded evidence bundle to `codex exec` in a read-only, ephemeral workspace. If a finding has already resolved, start the demo again before testing investigation.

The dashboard distinguishes configuration from execution: `gpt-5.6-sol · live` or `gpt-5.6 · live` means the last investigation succeeded, while the corresponding `· fallback` status means the request failed and the safe deterministic advisor was used. Check `/api/status` and `journalctl -u screamsiem` for the redacted failure reason.

## Submission details

- Chosen track: Developer Tools
- Code: [github.com/drbree82/screamsiem](https://github.com/drbree82/screamsiem)
- Primary Codex build session: `019f7866-4331-7fa0-a233-5c2ac4eb6464`
- Demo video: add the public YouTube URL to `SUBMISSION.md` after publishing

The repository is MIT licensed. The deterministic demo is self-contained and does not need SSH access, root, or an OpenAI key.

## Local development and provider setup

Requirements: Python 3.12+. Add Node.js/npm only when using local Codex authentication; the Linux installer installs them on apt-based systems when needed.

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

To use ChatGPT browser authentication on a local or headless machine, install the Codex CLI if needed, then run device login. The command prints a URL and one-time code instead of requiring a local browser. Paste both into a browser on another computer:

```bash
npm install --global @openai/codex
SCREAMSIEM_AI_PROVIDER=codex screamsiem auth login --device-auth
CODEX_MODEL=gpt-5.6-sol SCREAMSIEM_AI_PROVIDER=codex screamsiem serve
```

For the systemd installer, select `codex` when prompted. It installs the CLI when needed, stores its session under the service account's `CODEX_HOME`, and prints the same browser URL/code flow. Authentication is provided by Codex CLI; ScreamSIEM never reads or persists the Codex credentials.

To update an existing installed controller, rerun the same `siem.sh` command with its original `--install-dir`. The installer fast-forwards the checkout, preserves the enrollment data and existing Codex ChatGPT login, and rewrites the provider configuration. Updating does not automatically re-investigate old findings; use the dashboard or `POST /api/findings/{id}/investigate` for an active finding.

## Uninstall

These commands remove the ScreamSIEM services, local configuration, SSH keys, database, and dedicated `screamsiem` service account. Run each block on the named host, not on your workstation. Back up `/var/lib/screamsiem` first if you need to retain incident history.

On the controller machine:

```bash
sudo systemctl disable --now screamsiem.service
sudo rm -f /etc/systemd/system/screamsiem.service
sudo systemctl daemon-reload
sudo rm -rf /opt/screamsiem-controller /var/lib/screamsiem /etc/screamsiem
sudo userdel --remove screamsiem
```

On each monitored machine, first stop any optional demo listener. Set `SCREAMSIEM_DEMO_PORT` to the port used by the demo:

```bash
curl -fsSL https://screamsiem-installer.flrgx-cxz.workers.dev/demo.sh \
  | env SCREAMSIEM_DEMO_PORT=4444 bash -s -- --stop
```

Then remove the monitored-host enrollment service:

```bash
sudo systemctl disable --now screamsiem-enroll.timer
sudo systemctl stop screamsiem-enroll.service
sudo rm -f \
  /etc/systemd/system/screamsiem-enroll.service \
  /etc/systemd/system/screamsiem-enroll.timer \
  /usr/local/sbin/screamsiem-enroll
sudo systemctl daemon-reload
sudo rm -rf /etc/screamsiem
sudo userdel --remove screamsiem
```

The `userdel` command may report that a mail spool does not exist; that is harmless when the dedicated account has already been removed. The short-lived enrollment record in Cloudflare KV is not deleted by host uninstall and expires automatically.

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

## Deploy or update the Cloudflare installer Worker

The public curl URL is served by the Worker in [`cloudflare/installer-worker`](cloudflare/installer-worker). Its `assets.directory` points at `../../installers`, so deploying from that directory publishes the current `monitored.sh`, `siem.sh`, and `demo.sh` files.

First-time setup requires a Cloudflare login and an `ENROLLMENTS` KV namespace. Put the resulting namespace ID in `cloudflare/installer-worker/wrangler.jsonc`:

```bash
cd cloudflare/installer-worker
npx --yes wrangler@latest login
npx --yes wrangler@latest kv namespace create ENROLLMENTS --update-config
npx --yes wrangler@latest deploy
```

For later source or installer changes, deploy from the same directory:

```bash
npx --yes wrangler@latest deploy
```

The deployed URL becomes `SCREAMSIEM_INSTALLER_URL`. Verify the published assets before using them for enrollment:

```bash
curl -fsSL https://YOUR-WORKER.workers.dev/monitored.sh | head
curl -fsSL https://YOUR-WORKER.workers.dev/siem.sh | head
```

The current deployment is `https://screamsiem-installer.flrgx-cxz.workers.dev`.

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

## Architecture

The central FastAPI server owns SQLite persistence, baselines, deterministic detection, investigation orchestration, approvals, the dashboard and SSE. Each host has an SSH-native bridge with collectors and a loopback-only FastMCP boundary. GPT-5.6 sees bounded evidence and read-only function schemas; it never receives private keys, approval secrets, arbitrary shell access, or mutable tools during investigation.

The main components are deliberately explicit: `server`, `bridges`, `ssh`, `collectors`, `parsers`, `baselines`, `detections`, `investigator`, and `approvals`.

## How Codex and GPT-5.6 were used

Codex accelerated the workflow by turning the specification archive into a concrete implementation plan, scaffolding the Python package and SQLite model, writing the parser/detector/approval tests, iterating on the FastAPI/MCP integration, and repeatedly running the offline suite plus the loopback demo. Key implementation decisions were to keep detection deterministic, isolate each host behind a typed bridge, use fake SSH/GPT paths for reproducible tests, and require exact human approval before any mutation.

GPT-5.6 is the runtime investigator, not the detector or approver. It receives a bounded finding bundle, may request additional evidence through read-only MCP function calls, returns a validated structured assessment, and categorises recommendations as `mcp_action`, `manual_command`, or `advisory`. If the API is unavailable, the deterministic finding remains visible and the safe fallback explains that AI analysis is unavailable.

## Security and limitations

There is no generic shell MCP tool. Private keys and approval secrets never enter model input. Log/process content is treated as untrusted evidence. Mutation tokens bind the action ID, host, tool, exact canonical arguments, expiry and single-use nonce. Manual commands are display-only.

This is a Build Week MVP, not a production SOC. SQLite is not tamper-proof, a compromised host can lie to user-space collectors, polling can miss very short-lived events, and model-generated recommendations require human review. See [SECURITY.md](SECURITY.md).
