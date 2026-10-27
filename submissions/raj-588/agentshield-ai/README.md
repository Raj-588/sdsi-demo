# AgentShield AI — IntentLock

**Task-Bound Security for Autonomous AI Agents**
SDSI Digithon 2026 · AI Governance & Security

AgentShield is an independent security gateway that sits between an AI agent and
the enterprise tools it can call. Its policy engine, **IntentLock**, enforces
*task-bound authorization*: every proposed tool call is checked against a
trusted, server-side task scope **before** it can execute. The LLM may *propose*
actions; it is never the authority that *approves* them.

This stops prompt-injection attacks structurally rather than by detection: even
when the agent is fully fooled by a malicious instruction embedded in a
document, the gateway denies any call outside the authorized task scope, and the
sandbox executor is never invoked.

> **Scope honesty.** This is a 48-hour hackathon MVP, not a production-certified
> system. It is not claimed to be completely resistant to prompt injection.
> Implemented controls and future production requirements are listed explicitly
> in `docs/security_design.md`.

---

## Why it works (the one idea)

Role-based access control answers *"is this agent allowed to touch this
resource?"*. It does **not** answer *"is this specific action justified by what
the user actually asked for?"*. IntentLock answers the second question with a
deterministic, default-deny evaluation that is independent of the LLM.

```
User → Trusted Task Authorization → AI Agent (Ollama/mock) → proposed tool call
      → AgentShield Gateway → IntentLock (default-deny) → ALLOW / DENY / REQUIRES_APPROVAL
      → [only ALLOW] Sandbox Executor → Synthetic DB
      → Audit Log (SQLite) → Security Dashboard
```

Untrusted document text and tool responses are always treated as **data, never
instructions**. The LLM cannot create, widen, or approve its own authorization.

---

## Quick start (Windows 11)

```powershell
# 1. Setup (venv + deps + .env + DB init)
.\scripts\setup.ps1

# 2. Start the API + Ultra-Fast React Dashboard (terminal 1)
.\scripts\run_backend.ps1          # http://localhost:8000 (React UI & /docs for OpenAPI)

# 3. Optional: Start the Streamlit dashboard (terminal 2)
.\scripts\run_frontend.ps1         # http://localhost:8501

# 4. Run tests / the end-to-end demo
.\scripts\run_tests.ps1
.\scripts\run_e2e.ps1
```

### Choosing the LLM (Ollama, a hosted API key, or mock)

The LLM is on the **untrusted** side of the boundary — it only *proposes* calls.
Which model you use has **no effect** on the security guarantee, so you can pick
whichever is convenient. Set these in `.env`:

| Goal | `.env` |
|---|---|
| Local, offline | `LLM_PROVIDER=ollama` (+ `ollama pull qwen2.5:3b`) |
| Org OpenAI key | `LLM_PROVIDER=openai` · `LLM_API_KEY=sk-...` · `LLM_MODEL=gpt-4o-mini` |
| Azure / internal proxy | `LLM_PROVIDER=openai` · `LLM_API_KEY=...` · `LLM_BASE_URL=https://<host>/v1` |
| Anthropic key | `LLM_PROVIDER=anthropic` · `LLM_API_KEY=...` · `LLM_MODEL=claude-3-5-sonnet-latest` |
| No model at all | `FORCE_MOCK_AGENT=true` (deterministic demo) |

`openai` uses the standard `/chat/completions` tool-calling schema, which also
covers Azure OpenAI and most corporate LLM proxies. If the configured provider
is unreachable or the key is missing, the app falls back to the deterministic
mock automatically, so the demo always runs. Confirm the active provider at
`GET /api/v1/llm/status` or in the dashboard sidebar.

### Cross-platform (bash)

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=backend python -m app.db.init_db
PYTHONPATH=backend uvicorn app.main:app --port 8000      # terminal 1
AGENTSHIELD_API=http://localhost:8000 streamlit run frontend/dashboard.py  # terminal 2
python -m pytest
python scripts/run_e2e.py
```

---

## Test evidence (actual run)

`python -m pytest` → **50 passed** (unit + integration + security regression).

End-to-end (`scripts/run_e2e.py`), deterministic mock agent:

| Scenario | Tool | Decision | Reason | Execution |
|---|---|---|---|---|
| Injection | `read_report` | **ALLOW** | AUTHORIZED | EXECUTED |
| Injection | `export_customers` | **DENY** | TOOL_NOT_ALLOWED | BLOCKED |
| Injection | `delete_record` | **DENY** | TOOL_NOT_ALLOWED | BLOCKED |
| Approval | `export_customers` | **REQUIRES_APPROVAL** | APPROVAL_REQUIRED | BLOCKED |
| Cross-resource | `read_report` (Report B) | **DENY** | RESOURCE_NOT_ALLOWED | BLOCKED |

Aggregate: `allowed=1 denied=3 requires_approval=1 executed=1 blocked=4`.

---

## Project layout

```
backend/app/
  core/       config, enums
  db/         SQLAlchemy session + init/seed
  models/     ORM entities (7 tables)
  schemas/    Pydantic v2 request/response + typed contracts
  services/   intentlock (engine), gateway, agent, task, audit, scenarios
  tools/      strongly-typed sandbox tool registry + synthetic data
  api/        FastAPI routes
  main.py     app entrypoint (lifespan init, health, body-size limit)
backend/tests/  50 tests (engine, gateway, api, scenarios)
frontend/dashboard.py   5-screen Streamlit security dashboard
scripts/      PowerShell setup/run + run_e2e.py
docs/         architecture, api_specification, security_design, demo_script
data/         synthetic reports, customers, attack scenarios
```

See `docs/` for the architecture diagram, full API spec, security design and
limitations, and the five-minute demo script.

---

## Key API endpoints

`GET /health` · `GET /api/v1/scenarios` · `POST /api/v1/tasks` ·
`GET /api/v1/tasks/{id}` · `POST /api/v1/agent/run` ·
`POST /api/v1/gateway/evaluate` · `GET /api/v1/approvals` · `POST /api/v1/approvals/{id}/approve` ·
`GET /api/v1/audit` ·
`GET /api/v1/dashboard/metrics` · `GET /api/v1/llm/status`

Interactive docs at `/docs` when the backend is running.

---

## Known limitations

Development-only identity (fixed synthetic user, bound server-side — no real
authn/authz); keyword-free structural defense (we deliberately do **not** rely
on injection *detection*); single-node SQLite for the MVP (PostgreSQL-ready);
sandbox tools are simulations (no real data, email, or network egress);
live-LLM behavior depends on the chosen model's tool-calling quality. Production
hardening recommendations are in `docs/security_design.md`.
