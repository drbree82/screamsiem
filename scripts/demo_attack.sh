#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -lt 1 ]; then echo "usage: $0 host-name" >&2; exit 2; fi
echo "Run this reversible demo on the named host:"
echo "python3 -m http.server 4444 --directory /tmp"
echo "Terminate it with Ctrl-C after ScreamSIEM reports the listener."
