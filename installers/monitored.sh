#!/usr/bin/env bash
set -Eeuo pipefail

# ScreamSIEM monitored-host bootstrap. It never downloads or stores a private key.
WORKER_URL="${SCREAMSIEM_INSTALLER_URL:-https://screamsiem-installer.flrgx-cxz.workers.dev}"
ENROLLMENT_CODE="${SCREAMSIEM_ENROLLMENT_CODE:-}"
SSH_USER="${SCREAMSIEM_SSH_USER:-screamsiem}"
SSH_PORT="${SCREAMSIEM_SSH_PORT:-22}"
CONFIG_DIR=/etc/screamsiem
ENV_FILE="$CONFIG_DIR/enrollment.env"
die() { echo "screamsiem-monitored: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

metadata() {
  python3 -c 'import hashlib,json,platform,socket,subprocess,sys; u,p=sys.argv[1],int(sys.argv[2]); h=socket.gethostname(); m=open("/etc/machine-id").read().strip() if __import__("os").path.exists("/etc/machine-id") else h; a=[x for x in subprocess.check_output(["hostname","-I"],text=True).split() if ":" not in x and not x.startswith("127.")]; o=open("/etc/os-release").read()[:4000] if __import__("os").path.exists("/etc/os-release") else ""; print(json.dumps({"host_id":"host_"+hashlib.sha256(m.encode()).hexdigest()[:24],"hostname":h,"addresses":a,"ssh_port":p,"ssh_user":u,"os":o,"kernel":platform.release(),"installed_at":__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),"controller_key_installed":False},separators=(",",":")))' "$SSH_USER" "$SSH_PORT"
}

controller_key() {
  curl -fsS --retry 2 "$WORKER_URL/v1/enroll/$ENROLLMENT_CODE" | python3 -c 'import json,sys; print((json.load(sys.stdin).get("controller") or {}).get("public_key", ""))'
}

authorize_controller() {
  local key home auth
  key="$(controller_key 2>/dev/null || true)"
  [[ "$key" == ssh-ed25519\ * ]] || return 1
  [[ "$key" != *$'\n'* && "$key" != *$'\r'* ]] || die "controller key contains a newline"
  home="$(getent passwd "$SSH_USER" | cut -d: -f6)"
  [[ -n "$home" && -d "$home" ]] || die "home directory not found for $SSH_USER"
  install -d -m 700 -o "$SSH_USER" -g "$SSH_USER" "$home/.ssh"
  auth="$home/.ssh/authorized_keys"; touch "$auth"; chown "$SSH_USER:$SSH_USER" "$auth"; chmod 600 "$auth"
  authorized_key="no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty $key screamsiem-controller"
  grep -Fqx "$authorized_key" "$auth" 2>/dev/null || printf '%s\n' "$authorized_key" >> "$auth"
  python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["controller_key_installed"]=True; json.dump(d,open(p,"w"),separators=(",",":")); open(p,"a").write("\n")' "$CONFIG_DIR/host.json"
  systemctl disable --now screamsiem-enroll.timer >/dev/null 2>&1 || true
  echo "screamsiem-monitored: controller key installed for $SSH_USER"
}

if [[ "${1:-}" == "--poll" ]]; then
  [[ "$(id -u)" == 0 ]] || die "poll mode must run as root"
  [[ -r "$ENV_FILE" ]] || die "missing $ENV_FILE"
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  authorize_controller || true
  exit 0
fi

[[ "$(id -u)" == 0 ]] || die "run with sudo"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --enrollment-code) ENROLLMENT_CODE="${2:?missing code}"; shift 2 ;;
    --worker-url) WORKER_URL="${2:?missing worker URL}"; shift 2 ;;
    --ssh-user) SSH_USER="${2:?missing SSH user}"; shift 2 ;;
    --ssh-port) SSH_PORT="${2:?missing SSH port}"; shift 2 ;;
    -h|--help) sed -n '1,35p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ "$ENROLLMENT_CODE" =~ ^[A-Za-z0-9._:-]{12,128}$ ]] || die "pass a 12-128 character enrollment code"
[[ "$SSH_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid SSH user"
[[ "$SSH_PORT" =~ ^[0-9]+$ && "$SSH_PORT" -le 65535 ]] || die "invalid SSH port"
need curl; need python3; need getent; need systemctl
id "$SSH_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$SSH_USER"
for group in systemd-journal adm; do getent group "$group" >/dev/null 2>&1 && usermod -aG "$group" "$SSH_USER" || true; done
install -d -m 755 "$CONFIG_DIR"
metadata > "$CONFIG_DIR/host.json"; chmod 644 "$CONFIG_DIR/host.json"
payload="$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); d["enrollment_code"]=sys.argv[2]; print(json.dumps(d,separators=(",",":")))' "$(cat "$CONFIG_DIR/host.json")" "$ENROLLMENT_CODE")"
curl -fsS --retry 3 -X POST "$WORKER_URL/v1/enroll/$ENROLLMENT_CODE/hosts" -H 'content-type: application/json' --data-binary "$payload" >/dev/null || die "could not register with installer service"
printf 'WORKER_URL=%q\nENROLLMENT_CODE=%q\nSSH_USER=%q\n' "$WORKER_URL" "$ENROLLMENT_CODE" "$SSH_USER" > "$ENV_FILE"; chmod 600 "$ENV_FILE"
curl -fsSL --retry 3 "$WORKER_URL/monitored.sh" -o /usr/local/sbin/screamsiem-enroll; chmod 700 /usr/local/sbin/screamsiem-enroll
printf '%s\n' '[Unit]' 'Description=ScreamSIEM controller key enrollment' '[Service]' 'Type=oneshot' 'ExecStart=/usr/local/sbin/screamsiem-enroll --poll' > /etc/systemd/system/screamsiem-enroll.service
printf '%s\n' '[Unit]' 'Description=Poll for ScreamSIEM controller key' '[Timer]' 'OnBootSec=10s' 'OnUnitActiveSec=30s' 'Unit=screamsiem-enroll.service' '[Install]' 'WantedBy=timers.target' > /etc/systemd/system/screamsiem-enroll.timer
systemctl daemon-reload; systemctl enable --now screamsiem-enroll.timer
authorize_controller || true
echo "screamsiem-monitored: enrolled $SSH_USER@$SSH_PORT; waiting for controller key"
