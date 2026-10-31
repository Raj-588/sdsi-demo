# AI-EDR Inline Guardrail Platform

An inline, pre-LLM security layer (AI Endpoint Detection & Response). It stops **direct** and **indirect** prompt injection before ChatGPT, Gemini, Claude, coding agents, Samsung FabriX or Samsung AI Pro read a single token.

![AI-EDR overview](docs/ai-edr-overview.png)

- **Specification:** [enterprise_ai_security_guardrail_specification.md](enterprise_ai_security_guardrail_specification.md)
- **Architecture:** [architecture.md](architecture.md)
- **Demo script:** [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md) · **claude.ai / Gemini web demo:** [docs/BROWSER_DEMO.md](docs/BROWSER_DEMO.md)
- **Samsung feasibility:** [docs/SAMSUNG_FEASIBILITY.md](docs/SAMSUNG_FEASIBILITY.md)
- **Measured results:** [docs/BENCHMARK.md](docs/BENCHMARK.md)
- **Endpoint fleet (agent, control plane, persistent Risk DB, portal):** [docs/FLEET_PLATFORM.md](docs/FLEET_PLATFORM.md)
- **Deck and video:** [presentation/](presentation/)

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt onnxruntime tokenizers
.venv/bin/python demo/make_poisoned_files.py
./scripts/download_model.sh                      # optional Tier 2 DeBERTa-v3 ONNX model (recommended)
.venv/bin/uvicorn src.main:app --port 8080       # open http://localhost:8080/console
.venv/bin/python demo/run_demo.py                # every attack, without vs with AI-EDR
.venv/bin/python -m pytest -q tests
```

## How it works

| Stage | Module | What it does |
|---|---|---|
| 0. Adapters | `src/adapters/` | OpenAI, Gemini, Anthropic/Claude Code, FabriX and AI Pro payloads → `CanonicalAIEDRRequest`; sanitized content is written back in the provider's own format |
| 1. Collectors | `src/collectors/` | Turn prompts, files, RAG chunks, tool results and tool calls into trust-tagged segments. PDF/DOCX/HTML/Markdown hidden-layer detection: white text, 0-pt fonts, render mode 3, CSS-hidden text, metadata |
| 2. AI Risk Database | `src/risk_database/` | Aho-Corasick and regex signatures, DLP rules, semantic threat vectors, and the Falcon Loop promotion worker |
| 3. Security Guard | `src/ai_edr_guard/` | Hidden-trick unpacking (Unicode tags, zero-width characters, homoglyphs, Base64/hex/ROT13). **Tier 1** signatures and DLP · **Tier 2** DeBERTa-v3 ONNX classifier plus behavioral IOAs and agent process tree · **Tier 3** vector match. Decision engine, CDR stripper with spotlighting, Quarantine Vault |
| 4. AI Brain | `src/proxy_router/` | Streams clean input to the real provider, or answers from the built-in vulnerable mock LLM for offline demos |

**Integration modes:**
- **Reverse proxy:** change the `base_url` / `ANTHROPIC_BASE_URL` to point at the gateway.
- **Hook API:** call `POST /v1/ai-edr/inspect` (or `/inspect/simple`) before sending a request.
- **IDE hooks:** `integrations/claude_code/ai_edr_hook.py` works for Claude Code and Gemini CLI.
- **Browser extension:** `integrations/browser_extension/` protects claude.ai and gemini.google.com (prompts and file uploads).

**Endpoint fleet:** `agent/checkpointd` runs on each machine and checks what AI agents do: commands they run, files they read and connections they open. A Linux BPF LSM program in `agent/kernel/linux` adds in-kernel denial. The control plane (`src/control_plane`, `/v1/cp`) keeps the AI Risk DB in a database and ships it as gated, Ed25519-signed releases through CANARY → GA rings. The portal is at `/portal`. Run `./scripts/start_fleet_demo.sh`.

**Policy:** `config/ai_edr_policies.yaml` sets the mode per tenant: `BLOCK_AND_QUARANTINE`, `STRIP_AND_SANITIZE` or `AUDIT_ONLY`. It also holds DLP rules, thresholds and the FabriX/AI Pro field maps.

## Status and honest limits

- Inspects inputs only; model output is not inspected yet.
- The endpoint agent's user-space sensor kills malicious commands after they start; pre-exec denial needs the kernel checkpoint, whose Linux BPF code has not been compiled or run on a real kernel yet. See [docs/FLEET_PLATFORM.md](docs/FLEET_PLATFORM.md).
- Redis and Qdrant are represented by in-process stand-ins with the same interfaces; see `requirements-ml.txt`.
- The DeBERTa model is English-only. Korean text is covered by Korean signatures, IOAs and the local classifier.
- Known false positive: "Please ignore the previous email…"; see `docs/BENCHMARK.md`.
- The FabriX and AI Pro request formats are assumptions until Samsung provides the real ones.
