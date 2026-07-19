#!/usr/bin/env bash
set -Eeuo pipefail

# ScreamSIEM controller bootstrap.
WORKER_URL="${SCREAMSIEM_INSTALLER_URL:-https://screamsiem-installer.flrgx-cxz.workers.dev}"
ENROLLMENT_CODE="${SCREAMSIEM_ENROLLMENT_CODE:-}"
REPO_URL="${SCREAMSIEM_REPO_URL:-https://github.com/drbree82/screamsiem.git}"
INSTALL_DIR="${SCREAMSIEM_INSTALL_DIR:-/opt/screamsiem}"
DATA_DIR="${SCREAMSIEM_DATA_DIR:-/var/lib/screamsiem}"
CONFIG_DIR="${SCREAMSIEM_CONFIG_DIR:-/etc/screamsiem}"
KEY_DIR="$CONFIG_DIR/ssh"; DB_PATH="$DATA_DIR/screamsiem.db"
die() { echo "screamsiem-siem: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
[[ "$(id -u)" == 0 ]] || die "run with sudo"
while [[ $# -gt 0 ]]; do case "$1" in --enrollment-code) ENROLLMENT_CODE="${2:?missing code}"; shift 2;; --worker-url) WORKER_URL="${2:?missing URL}"; shift 2;; --repo-url) REPO_URL="${2:?missing URL}"; shift 2;; --install-dir) INSTALL_DIR="${2:?missing install directory}"; shift 2;; --data-dir) DATA_DIR="${2:?missing data directory}"; shift 2;; --config-dir) CONFIG_DIR="${2:?missing config directory}"; shift 2;; --cidr) SCREAMSIEM_CIDR="${2:?missing CIDR}"; shift 2;; -h|--help) sed -n '1,28p' "$0"; exit 0;; *) die "unknown option: $1";; esac; done
KEY_DIR="$CONFIG_DIR/ssh"; DB_PATH="$DATA_DIR/screamsiem.db"
[[ "$ENROLLMENT_CODE" =~ ^[A-Za-z0-9._:-]{12,128}$ ]] || die "pass the same enrollment code used on hosts"
need curl; need python3; need ssh; need ssh-keygen; need ip; need systemctl; need sudo
if command -v apt-get >/dev/null 2>&1; then apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git python3-venv openssh-client iproute2 openssl nmap nodejs npm >/dev/null; fi
id screamsiem >/dev/null 2>&1 || useradd --create-home --shell /bin/bash screamsiem
if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" pull --ff-only
else
  if [[ -e "$INSTALL_DIR" ]]; then
    [[ -d "$INSTALL_DIR" && -z "$(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]] || die "$INSTALL_DIR exists and is not a ScreamSIEM checkout; rerun with --install-dir /opt/screamsiem-controller"
  else
    install -d -m 755 "$(dirname "$INSTALL_DIR")"
  fi
  git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
fi
install -d -m 755 "$DATA_DIR" "$CONFIG_DIR" "$KEY_DIR"; chown -R screamsiem:screamsiem "$INSTALL_DIR" "$DATA_DIR"; chmod 700 "$KEY_DIR"
chown -R screamsiem:screamsiem "$KEY_DIR"
python3 -m venv "$INSTALL_DIR/.venv"; "$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip; "$INSTALL_DIR/.venv/bin/pip" install --quiet -e "$INSTALL_DIR"; chown -R screamsiem:screamsiem "$INSTALL_DIR"
if [[ ! -f "$KEY_DIR/id_ed25519" ]]; then sudo -u screamsiem ssh-keygen -q -t ed25519 -N '' -f "$KEY_DIR/id_ed25519" -C screamsiem-controller; fi
chown -R screamsiem:screamsiem "$KEY_DIR"; chmod 600 "$KEY_DIR/id_ed25519"; chmod 644 "$KEY_DIR/id_ed25519.pub"
CONTROLLER_ADDRESS="${SCREAMSIEM_CONTROLLER_ADDRESS:-$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -1)}"; CONTROLLER_ADDRESS="${CONTROLLER_ADDRESS:-$(hostname -I | awk '{print $1}')}"
payload="$(python3 -c 'import json,sys; print(json.dumps({"public_key":open(sys.argv[1]).read().strip(),"controller_address":sys.argv[2],"controller_user":"screamsiem"},separators=(",",":")))' "$KEY_DIR/id_ed25519.pub" "$CONTROLLER_ADDRESS")"
curl -fsS --retry 3 -X POST "$WORKER_URL/v1/enroll/$ENROLLMENT_CODE/controller" -H 'content-type: application/json' --data-binary "$payload" >/dev/null || die "could not publish controller key"
AI_PROVIDER="${SCREAMSIEM_AI_PROVIDER:-}"
OPENAI_API_KEY="${OPENAI_API_KEY:-}"
if [[ -z "$OPENAI_API_KEY" && -r "$CONFIG_DIR/screamsiem.env" ]]; then
  OPENAI_API_KEY="$(sed -n 's/^OPENAI_API_KEY=//p' "$CONFIG_DIR/screamsiem.env" | tail -1)"
fi
if [[ -z "$AI_PROVIDER" && -r /dev/tty ]]; then
  read -r -p 'AI provider [codex/api/fallback] (default: api): ' AI_PROVIDER < /dev/tty
  AI_PROVIDER="${AI_PROVIDER:-api}"
fi
AI_PROVIDER="${AI_PROVIDER:-api}"
[[ "$AI_PROVIDER" == "codex" || "$AI_PROVIDER" == "api" || "$AI_PROVIDER" == "fallback" ]] || die "SCREAMSIEM_AI_PROVIDER must be codex, api, or fallback"
install -d -m 700 "$CONFIG_DIR/codex"; chown screamsiem:screamsiem "$CONFIG_DIR/codex"
if [[ "$AI_PROVIDER" == "codex" ]]; then
  OPENAI_API_KEY=""
  if ! command -v codex >/dev/null 2>&1; then
    need npm
    npm install --global --quiet @openai/codex || die 'could not install the Codex CLI'
  fi
  echo 'Starting headless Codex device login. Copy the printed URL and code into a browser on another computer.'
  sudo -u screamsiem -H env CODEX_HOME="$CONFIG_DIR/codex" "$INSTALL_DIR/.venv/bin/screamsiem" auth login --device-auth < /dev/tty || die 'Codex device login failed; rerun `sudo -u screamsiem -H CODEX_HOME='"$CONFIG_DIR/codex"' codex login --device-auth`'
elif [[ "$AI_PROVIDER" == "api" && -z "$OPENAI_API_KEY" && -r /dev/tty ]]; then
  read -r -s -p 'OpenAI API key (optional; press Enter for deterministic fallback): ' OPENAI_API_KEY < /dev/tty
  echo
fi
INTERNAL_SECRET="${SCREAMSIEM_INTERNAL_SECRET:-$(openssl rand -hex 32)}"; APPROVAL_SECRET="${SCREAMSIEM_APPROVAL_SECRET:-$(openssl rand -hex 32)}"
printf 'SCREAMSIEM_HOST=127.0.0.1\nSCREAMSIEM_PORT=8080\nSCREAMSIEM_DATABASE=%s\nSCREAMSIEM_INTERNAL_SECRET=%s\nSCREAMSIEM_APPROVAL_SECRET=%s\nSCREAMSIEM_AI_PROVIDER=%s\nCODEX_HOME=%s\nOPENAI_MODEL=gpt-5.6\nOPENAI_API_KEY=%s\n' "$DB_PATH" "$INTERNAL_SECRET" "$APPROVAL_SECRET" "$AI_PROVIDER" "$CONFIG_DIR/codex" "$OPENAI_API_KEY" > "$CONFIG_DIR/screamsiem.env"
chown root:screamsiem "$CONFIG_DIR/screamsiem.env"; chmod 640 "$CONFIG_DIR/screamsiem.env"
KNOWN_HOSTS="$KEY_DIR/known_hosts"; touch "$KNOWN_HOSTS"; chown screamsiem:screamsiem "$KNOWN_HOSTS"; chmod 600 "$KNOWN_HOSTS"
CIDR="${SCREAMSIEM_CIDR:-$(ip route show scope link 2>/dev/null | awk '$1 ~ /^[0-9].*\/[0-9]+$/ {print $1; exit}')}"
CANDIDATES="$CONFIG_DIR/candidates.txt"; : > "$CANDIDATES"
curl -fsS "$WORKER_URL/v1/enroll/$ENROLLMENT_CODE" | python3 -c 'import json,sys; d=json.load(sys.stdin); [print(a) for h in d.get("hosts",[]) for a in h.get("addresses",[])]' >> "$CANDIDATES" || true
ip neigh show 2>/dev/null | awk '$1 ~ /^[0-9]/ {print $1}' >> "$CANDIDATES" || true
if command -v nmap >/dev/null 2>&1 && [[ -n "$CIDR" ]]; then nmap -sn -n -oG - "$CIDR" 2>/dev/null | awk '/Up$/{print $2}' >> "$CANDIDATES" || true; fi
sort -u "$CANDIDATES" -o "$CANDIDATES"
found=0
for attempt in $(seq 1 12); do
  while read -r address; do
    [[ -n "$address" ]] || continue
    info="$(ssh -i "$KEY_DIR/id_ed25519" -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN_HOSTS" "screamsiem@$address" 'cat /etc/screamsiem/host.json' 2>/dev/null || true)"
    [[ "$info" == \{* ]] || continue
    name="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("hostname","screamsiem-host"))' "$info")"; port="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("ssh_port",22))' "$info")"; host_address="$(python3 -c 'import json,sys; print((json.loads(sys.argv[1]).get("addresses") or [sys.argv[2]])[0])' "$info" "$address")"
    SCREAMSIEM_DATABASE="$DB_PATH" "$INSTALL_DIR/.venv/bin/screamsiem" host add --name "$name" --address "$host_address" --port "$port" --user screamsiem --identity "$KEY_DIR/id_ed25519" --known-hosts "$KNOWN_HOSTS" || true
    found=$((found+1))
  done < "$CANDIDATES"
  [[ "$found" -gt 0 ]] && break
  sleep 5
done
printf '%s\n' '[Unit]' 'Description=ScreamSIEM Linux security monitor' 'After=network-online.target' 'Wants=network-online.target' '[Service]' 'Type=simple' 'User=screamsiem' 'Group=screamsiem' "WorkingDirectory=$INSTALL_DIR" "EnvironmentFile=$CONFIG_DIR/screamsiem.env" "ExecStart=$INSTALL_DIR/.venv/bin/screamsiem serve" 'Restart=on-failure' 'RestartSec=5' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/screamsiem.service
systemctl daemon-reload; systemctl enable screamsiem.service; systemctl restart screamsiem.service
echo "screamsiem-siem: enrolled $found host(s); dashboard is http://127.0.0.1:8080"
