#!/usr/bin/env bash
set -Eeuo pipefail

# Safe, reversible ScreamSIEM demo: create a temporary listener for detection.
PORT="${SCREAMSIEM_DEMO_PORT:-4444}"
DURATION="${SCREAMSIEM_DEMO_DURATION:-120}"
PID_FILE="/tmp/screamsiem-demo-http.pid"
LOG_FILE="/tmp/screamsiem-demo-http.log"
die() { echo "screamsiem-demo: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

if [[ "${1:-}" == "--stop" ]]; then
  if [[ -r "$PID_FILE" ]]; then
    pid="$(cat "$PID_FILE")"
    kill "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "screamsiem-demo: stopped listener on port $PORT"
  else
    echo "screamsiem-demo: no demo listener found"
  fi
  exit 0
fi

need python3
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1024 && "$PORT" -le 65535 ]] || die "invalid demo port"
[[ "$DURATION" =~ ^[0-9]+$ && "$DURATION" -ge 5 && "$DURATION" -le 3600 ]] || die "invalid demo duration"
if [[ -r "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  die "demo listener is already running; use --stop first"
fi

python3 -m http.server "$PORT" --bind 0.0.0.0 >"$LOG_FILE" 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$PID_FILE"
(sleep "$DURATION"; kill "$pid" 2>/dev/null || true; rm -f "$PID_FILE") >/dev/null 2>&1 &
echo "screamsiem-demo: listener started on 0.0.0.0:$PORT for ${DURATION}s (pid $pid)"
