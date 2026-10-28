#!/usr/bin/env bash
# Starts a clean AI-EDR stack for the live Claude Code demo.
#   :8080  hook/console server (mock upstream)   :8081  proxy server (forwards to the real Anthropic API)
set -euo pipefail
cd "$(dirname "$0")/.."
pkill -f "uvicorn src.main:app" 2>/dev/null || true
rm -f data/quarantine.db data/siem_alerts.jsonl
.venv/bin/python demo/make_poisoned_files.py >/dev/null
.venv/bin/uvicorn src.main:app --port 8080 > data/server.log 2>&1 &
AI_EDR_UPSTREAM_MODE=real AI_EDR_DATA_DIR="$PWD/data/real" .venv/bin/uvicorn src.main:app --port 8081 > data/server-real.log 2>&1 &
until curl -sf localhost:8080/healthz >/dev/null && curl -sf localhost:8081/healthz >/dev/null; do sleep 0.5; done
echo "AI-EDR ready → console: http://localhost:8080/console#feed"
open "http://localhost:8080/console#feed" 2>/dev/null || true
