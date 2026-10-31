#!/usr/bin/env bash
# Endpoint fleet demo: gateway + control plane + portal on :8080, two checkpointd agents, attack simulation.
#   ./scripts/start_fleet_demo.sh             full run (attack + learning loop)
#   ./scripts/start_fleet_demo.sh --idle      only start the stack and the agents
# Stop:  pkill -f agent.checkpointd; pkill -f "uvicorn src.main:app"
set -euo pipefail
cd "$(dirname "$0")/.."
D=data/fleet_demo
pkill -f "agent.checkpointd" 2>/dev/null || true
pkill -f "uvicorn src.main:app" 2>/dev/null || true
sleep 1
rm -rf data/control_plane.db* data/quarantine.db data/siem_alerts.jsonl "$D"
mkdir -p "$D/workspace"
.venv/bin/python demo/make_poisoned_files.py >/dev/null
.venv/bin/uvicorn src.main:app --port 8080 > data/server.log 2>&1 &
until curl -sf localhost:8080/healthz >/dev/null; do sleep 0.5; done

# CANARY endpoint: watches the agent workspace and treats `demo_ai_agent` as an AI agent.
.venv/bin/python -m agent.checkpointd --server http://127.0.0.1:8080 --state-dir "$D/agent-canary" \
  --watch "$D/workspace" --ai-process demo_ai_agent --ring CANARY --heartbeat 3 > "$D/agent-canary.log" 2>&1 &
# BROAD endpoint: stands in for the rest of the fleet (same machine, so it watches nothing to avoid duplicates).
.venv/bin/python -m agent.checkpointd --server http://127.0.0.1:8080 --state-dir "$D/agent-broad" \
  --ai-process fleet_peer_only --ring BROAD --heartbeat 3 > "$D/agent-broad.log" 2>&1 &
sleep 6
echo "Portal:  http://localhost:8080/portal      Agent log: $D/agent-canary.log"
open "http://localhost:8080/portal" 2>/dev/null || true
[[ "${1:-}" == "--idle" ]] && exit 0

echo; echo "== Step 1: hijacked AI coding agent on the CANARY endpoint"
.venv/bin/python demo/agent_attack_sim.py "$D/workspace"
sleep 3
grep -E "FILE|EXEC" "$D/agent-canary.log" | sed -E 's#^.*(FILE|EXEC) #\1 #' | cut -c1-150
echo; echo "== Step 2: the gateway learns a zero-day; signed content reaches CANARY first"
(cd demo && ../.venv/bin/python fleet_learning_step.py http://127.0.0.1:8080)
