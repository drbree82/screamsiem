#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export SCREAMSIEM_DEMO=1
export SCREAMSIEM_DATABASE="${SCREAMSIEM_DATABASE:-./data/demo.db}"
export SCREAMSIEM_INTERNAL_SECRET="${SCREAMSIEM_INTERNAL_SECRET:-demo-internal}"
export SCREAMSIEM_APPROVAL_SECRET="${SCREAMSIEM_APPROVAL_SECRET:-demo-approval}"
python3 -m uvicorn screamsiem.server:app --host 127.0.0.1 --port "${SCREAMSIEM_PORT:-8080}" &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
python3 scripts/wait_for_ready.py "http://127.0.0.1:${SCREAMSIEM_PORT:-8080}/healthz"
python3 - <<'PY'
import os, urllib.request
port=os.environ.get('SCREAMSIEM_PORT','8080')
url=f'http://127.0.0.1:{port}/api/demo/trigger'
print(f'Dashboard: http://127.0.0.1:{port}/')
print('Triggering deterministic suspicious listener...')
print(urllib.request.urlopen(urllib.request.Request(url,method='POST')).read().decode())
print('Leave this process running to view the dashboard; Ctrl-C stops the demo.')
PY
wait "$pid"
