# Discussion Log: AI-EDR / CheckPoint Zero

Key design and product discussions, newest last. Each entry is dated and records what was discussed and what was decided, plus open questions.

Detailed designs live in [architecture.md](architecture.md). This file records the *why*.

---

## 2026-10-28: Role of the AI Risk Database

**Discussion:** What does the AI Risk Database do, and why have one?

**Key points**
- The Risk DB is the **shared memory of known attacks** (Stage 2, "The Threat Data"). The guard (Stage 3) makes the decisions; the Risk DB is what the guard *knows*. Every platform (ChatGPT, Gemini, Claude, FabriX, AI Pro, IDEs, browser) checks the same database.
- It has three stores (`src/risk_database/`):
  1. **Hot Signature Cache** (`signature_store.py`): phrase signatures in an Aho-Corasick trie (one pass, < 2 ms), regex rules and DLP patterns. A version number invalidates the verdict cache.
  2. **Semantic Threat Vector DB** (`vector_threat_db.py` + `embedder.py`): 2048-d hashing embeddings with cosine top-k. τ = 0.80 catches reworded attacks (Tier 3). Each entry has a status: ACTIVE, PENDING_REVIEW or REVERTED.
  3. **Threat Feed / learning loop** (`falcon_threat_feed.py`): quarantined attacks become candidates. Gates: DLP skip, no self-reinforcement, allow-list, dedupe (≥ 0.97), rate limit. Then it either auto-promotes (HIGH and score ≥ 0.85) or sends the entry to analyst review.
- Live state at the time: 37 phrases (9 learned), 9 regex rules, 7 DLP patterns; 32 vectors (17 seed, 13 learned, 2 pending).
- **Why a DB and not just a better model:** it updates from one example in seconds, is shared across vendors, is explainable (every block cites an entry ID), and is reversible (one-call revert).

**Known limits:** state is in-memory and lost on restart. The hashing embedder matches wording more than meaning. Production plan: Redis + Qdrant/pgvector + a neural embedder.

---

## 2026-10-28: What ONNX is used for

**Discussion:** What is ONNX really used for in the project?

**Key points**
- ONNX is a portable model format. ONNX Runtime runs neural networks **locally on CPU**, with no PyTorch, no GPU and no cloud API.
- It runs the **Tier 2 DeBERTa-v3 prompt-injection classifier** (`protectai/deberta-v3-base-prompt-injection-v2`). This tier catches **attacks never seen before**; Tiers 1 and 3 only catch known attacks and their variants.
- Why local: confidential data never leaves the company, it works air-gapped, and there are no per-call costs.
- Tuning lessons:
  - Prose-only windows: code false positives went from 70% to 0%.
  - Only the top 8 windows are scored: p95 ≈ 950 ms on large files.
  - Fragments under 5 words go to the local model.
  - English only; Korean is handled by signatures and IOAs.
  - Corroboration cap: the model alone can't block untrusted content.
  - Falls back to a local LR classifier if the model is missing.
- An optional ONNX embedder (`AI_EDR_EMBEDDER=onnx`) is the upgrade path for Tier 3.

---

## 2026-10-31: CheckPoint Zero Kernel Agent

**Discussion:** Design an agent that acts as a kernel-level checkpoint.

**Decision:** Documented as **§19 in architecture.md**.

**Key points**
- The current integrations (extension, hooks, proxy, SDK) can be bypassed by using a different tool. A kernel agent protects the **machine**, not the tool, and also covers shadow AI and local models.
- There are four checkpoints:
  - **File**: LSM `file_open`, ES `AUTH_OPEN` or a minifilter. Poisoned files are served as sanitized shadow copies.
  - **Exec**: catches tool hijack via the agent process tree.
  - **Network**: transparent redirect to the local AI-EDR proxy, plus egress deny.
  - **TLS plaintext tap**: uprobes, observe-only.
- The user-space daemon `checkpointd` reuses the existing engine, Risk DB and adapters. The kernel stays thin and only enforces "ask the agent".
- Roadmap: P0 Linux eBPF prototype (days) → P1 daemon (weeks) → P2 macOS ES / Windows minifilter (months, needs an entitlement and driver signing) → P3 tamper protection and fleet management.

**Also done:** created the private repo https://github.com/Raj-588/ai-edr-guardrail (branch `main`, local remote `aiedr`).

---

## 2026-10-31: CrowdStrike Falcon vs Palo Alto Cortex XDR: making this a sellable product

**Discussion:** Research both products and design a production-ready, sellable solution.

**Team's starting findings**
1. Kernel programming will be needed to block activity on any system.
2. An AI Risk DB will hold attack details and intelligence.

### Verdict
- **Don't build another full EDR/XDR.** Both incumbents have more than 10 years of kernel sensors, data lakes and threat intelligence.
- **Both have entered our space:**
  - CrowdStrike **Falcon AIDR** was generally available on 15 Dec 2025. It covers prompt injection and jailbreaks, and was extended to endpoints, SaaS and cloud in Mar 2026.
  - Palo Alto has **Prisma AIRS** and bought **Protect AI** (2025). It announced the **Koi Security** purchase ($300M, Feb 2026) to add "Agentic Endpoint Security" for coding agents.
  - This proves the market exists and buyers pay.
- **Our wedge:** a vendor-neutral, on-prem / sovereign **AI-agent endpoint checkpoint** that **sanitizes** instead of only blocking and is multilingual (Korean first). It **coexists** with Falcon/Cortex and isn't a replacement. First buyers: regulated and data-sensitive enterprises (Samsung, finance, government, defence).

### Assessment of the team's findings
| Finding | Assessment |
|---|---|
| Kernel programming needed | **Partly true.** We need kernel-level *enforcement points*, but after the July 2024 CrowdStrike outage, custom kernel code is a liability. Use OS frameworks (eBPF LSM, Apple Endpoint Security, Windows minifilter/WFP, and later Microsoft's user-mode endpoint security platform from the Windows Resiliency Initiative). Thin kernel, all logic in user space |
| AI Risk DB holds the attacks | **True, and it is the moat.** It must be production-grade: versioned, **signed**, staged rollout, multi-tenant. The CrowdStrike outage came from an untested *content* update, and Risk DB updates are content |

### Comparison
| Dimension | CrowdStrike Falcon | Palo Alto Cortex XDR / XSIAM |
|---|---|---|
| Core idea | One light agent + cloud Threat Graph; endpoint-first | Agent + Cortex Data Lake + analytics; network + endpoint |
| Sensor | Windows kernel driver (cause of the Jul 2024 outage, ~8.5M machines); Linux kernel module or user-mode eBPF | Local analysis + WildFire intelligence; data forwarded to XDL |
| Detection | IOAs, ML, threat intel, managed hunting | Behavioural analytics across endpoint, network and cloud; WildFire sandbox |
| AI security | Falcon AIDR (prompt layer, 180+ techniques, Copilot Studio agents) | Prisma AIRS (runtime, red-team, supply chain, AI Agent Gateway) + Koi (agentic endpoint) |
| Strengths | Endpoint telemetry, MITRE results, ecosystem | Platform consolidation, firewall install base |
| Openings for us | Cloud-only data plane (sovereignty); premium price; AI coverage depends on which collectors are deployed | AI security split across acquisitions; complex to buy |
| Price (indicative) | Published list ≈ $60–185 per device/year (Go → Enterprise) | Mostly quote-based |

**Copy:**
- One agent with many modules.
- Behaviour-based detection (IOAs).
- Instant cloud-to-endpoint intelligence.
- A public, mapped detection catalogue.
- Marketplace integrations (Falcon Foundry/Fusion, Cortex XSIAM marketplace).

**Avoid:**
- Parsing untrusted content in the kernel.
- Pushing content updates to every machine at once.
- Forcing customer data into the vendor's cloud.

### Our differentiators
| Differentiator | Why incumbents don't match it today |
|---|---|
| Sanitize, don't just block (CDR for AI) | Work continues: the agent reads the file minus the hidden commands |
| Fully on-prem / air-gapped (local ONNX + local Risk DB) | Incumbents depend on their cloud; sovereignty buyers can't use that |
| Vendor-neutral across ChatGPT, Gemini, Claude, Copilot, FabriX, AI Pro, coding agents, local LLMs | Each incumbent is strongest in its own stack |
| Korean / multilingual detection | English-first engines miss Korean attacks |
| One story per attack: prompt → file → exec → network | Palo Alto had to buy Koi for this |
| Sends detections *into* Falcon/Cortex/Splunk | An add-on purchase, not a rip-and-replace |

### ⚠️ Trademark: rename before selling
"Falcon technique" and "Falcon Loop" use CrowdStrike's product brand. Candidate names: **Zero Loop**, **Immunity Loop**, **Herd Immunity Engine**. Avoid *Sentinel* (SentinelOne, Microsoft Sentinel) and *Cortex* (Palo Alto). *Check Point* is also a security company's brand (Check Point Software), so get a trademark search on "CheckPoint Zero" before using it commercially.

### Production architecture (target)
```
ENDPOINT                                   CONTROL PLANE (SaaS or on-prem, same build)
┌───────────────────────────────┐          ┌─────────────────────────────────────────┐
│ Kernel layer (thin, OS APIs)  │          │ Fleet manager · policy · RBAC · SSO     │
│ eBPF LSM / Apple ES+NE /      │          │ Risk DB service (global + tenant)       │
│ Win minifilter+WFP            │  mTLS    │ Content build → test → sign → ring      │
│ → only "ask the agent"        │◄────────►│   rollout                               │
├───────────────────────────────┤          │ Learning loop (review queue, revert)    │
│ checkpointd (user space)      │          │ Quarantine vault · forensics            │
│ AI-process ID · CDR · Tier 1  │          │ Connectors: Splunk, Sentinel, XSIAM,    │
│   T2 ONNX · T3 · IOAs         │          │   Falcon, ServiceNow                    │
│ Local Risk DB replica (signed)│          └────────────────┬────────────────────────┘
│ Local proxy · enforcer        │                           │ opt-in, anonymized
│ Watchdog · safe mode          │          ┌────────────────▼────────────────────────┐
└───────────────────────────────┘          │ Global Threat Intel (our research team, │
Also: browser ext, IDE hooks, gateway      │ red-team corpus, customer-shared IOCs)  │
                                           └─────────────────────────────────────────┘
```

### AI Risk DB: production design
- **Three tiers:**
  - **Global** (our curated intelligence, shipped to all customers).
  - **Tenant** (the customer's own learned entries and allow-lists; never leaves the tenant).
  - **Endpoint replica** (read-only, signed, works offline).
- **Entry schema:** id, type (phrase / regex / vector / DLP / IOA rule / file hash), technique mapped to **OWASP LLM Top 10** and **MITRE ATLAS** IDs, severity, language, source (seed / learned / intel / analyst), status, confidence, first/last seen, hit counts, false-positive reports, signer, version.
- **Content pipeline:** build → automated replay against the attack corpus **and** a benign corpus (the false-positive gate) → sign → **ring rollout** (internal → 1% → 10% → all), with automatic rollback on error or false-positive spikes. This is the direct lesson from the CrowdStrike outage.
- **Storage:** Postgres (source of truth) + Qdrant/pgvector (vectors) + Redis (hot cache, pub/sub); bundles distributed as signed delta files.
- **Exports:** STIX/TAXII for sharing intelligence; a public detection catalogue (marketing asset, cf. "180+ techniques").

### Kernel / sensor safety rules
1. No content parsing in kernel space, ever.
2. Kernel hooks fail open on agent timeout, unless the tenant policy explicitly says fail-closed.
3. A boot-loop guard: after two crashes, automatically drop to safe mode (monitor only).
4. Prefer OS-provided frameworks over custom drivers. Track Microsoft's user-mode security platform for Windows.
5. Sensor code updates and content updates use separate channels, each with ring rollout.

### Production requirements checklist
- **Multi-tenant control plane:** SSO/SCIM, RBAC, audit log, data residency per region (Korea first).
- **Packaging:** MSI/PKG/DEB/RPM; MDM deployment (Intune, Jamf, Knox, Ansible); coexistence tests with Falcon, Cortex and Defender.
- **Performance budget:** < 1% CPU idle, < 150 MB RAM, prompt p95 < 50 ms.
- **Certifications:** SOC 2 Type II, ISO 27001; **ISMS-P** and **CC** for Korean public and financial customers; GDPR.
- **Quality:** an independent detection benchmark (our fresh-set method) published every quarter.

### Go-to-market (draft)
- **Pricing:**
  - Per-endpoint add-on of about $3–8 per device per month. This sits under incumbent EDR pricing and positions us as an add-on.
  - Plus a per-gateway or server tier for FabriX- and RAG-style platforms.
- **Channels:** Samsung SDS as design partner and reseller; marketplace apps for Falcon and XSIAM; Korean MSSPs.
- **Land:** coding agents and AI chat in R&D. **Expand:** RAG pipelines, agent platforms, all employees.

### Roadmap (production)
| Phase | Scope | Team | Time |
|---|---|---|---|
| 0 | Today's gateway + P0 eBPF prototype; rename the brand | Current team | 1 month |
| 1 | `checkpointd` (Linux + macOS ES), persistent Risk DB, signed ring rollout, control plane MVP | 6–8 engineers | 4–6 months |
| 2 | Windows (minifilter/WFP), tamper protection, SIEM/XSIAM/Falcon connectors, SOC 2 | +4 | 6 months |
| 3 | Public detection catalogue, threat-intel team, marketplace listings, ISMS-P/CC | +3 | 6–9 months |

### Risks
- **Incumbents bundle AI security for free.** Answer: on-prem, sanitize instead of block, multilingual, neutral.
- **OS vendors restrict kernel access.** Answer: we already use OS frameworks.
- **False positives kill adoption.** Answer: the false-positive gate in the content pipeline, plus audit-only mode first.
- **Endpoint performance and stability.** Answer: thin kernel, safe mode, ring rollout.

### Open questions
- Final brand name and trademark search.
- First design-partner customer (Samsung SDS?) and the deployment model it needs (SaaS vs on-prem).
- Whether Windows is in phase 1 (most enterprise endpoints run Windows) or phase 2 (lower risk).

### Sources
- [CrowdStrike Falcon AIDR GA announcement](https://www.crowdstrike.com/en-us/blog/crowdstrike-secures-growing-ai-attack-surface-with-falcon-aidr)
- [Falcon AIDR product page](https://www.crowdstrike.com/en-gb/platform/falcon-aidr-ai-detection-and-response/)
- [Falcon AIDR launch: SecurityBrief](https://securitybrief.co.uk/story/crowdstrike-unveils-falcon-aidr-to-secure-ai-prompts)
- [Prisma AIRS introduction: Palo Alto Networks](https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-introduces-prisma-airs--the-foundation-on-which-ai-security-thrives)
- [Protect AI acquisition](https://convergedigest.com/palo-alto-networks-to-acquire-protect-ai/?amp=1)
- [Cortex XDR architecture docs](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-overview/cortex-xdr-architecture.html)
- [Cortex XSIAM architecture docs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Cortex-XSIAM-architecture)
- [What's new in Cortex, July 2026](https://www.paloaltonetworks.com/blog/security-operations/whats-new-in-cortex-july-2026.md/)
- [CrowdStrike outage and kernel access: Infosecurity](https://www.infosecurity-magazine.com/news/crowdstrike-apologizes-outage/)
- [CrowdStrike rollout process changes: SecurityWeek](https://www.securityweek.com/crowdstrike-overhauls-testing-and-rollout-procedures-to-avoid-bsod-crashes/amp/)
- [Windows Resiliency Initiative: Microsoft](https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise)
- [Microsoft limits kernel access: Help Net Security](https://www.helpnetsecurity.com/2024/11/19/windows-kernel-security-vendors/)
- [Windows security redesign status: Cybersecurity Dive](https://www.cybersecuritydive.com/trendline/software-cyber-security/257)
- [CrowdStrike vs Palo Alto: TechRepublic](https://www.techrepublic.com/article/crowdstrike-vs-palo-alto/)
- [Endpoint security pricing benchmarks 2026](https://costbench.com/stats/endpoint-security-pricing-2026/)

Vendor efficacy figures and third-party price figures are unverified. Confirm them before using any in a sales document.

---

## 2026-10-31: Built the endpoint agent, control plane, persistent AI Risk DB and fleet portal

**Discussion:** "Code everything: agent, dashboard portal and DB." This is the first implementation of the kernel-checkpoint direction (§19) and of the product design above. Details are in [docs/FLEET_PLATFORM.md](docs/FLEET_PLATFORM.md) and architecture.md §20.

**What was built**
- **`checkpointd` endpoint agent** (`agent/checkpointd`):
  - Exec, file and egress checkpoints, scoped to processes descended from an AI agent.
  - Kill / sanitize / quarantine in ENFORCE mode; alert only in MONITOR mode.
  - Safe mode after 2 unclean exits.
  - Offline outbox.
  - Signed content with the last good bundle kept.
- **Linux kernel checkpoint** (`agent/kernel/linux`): a BPF LSM program plus a libbpf loader.
  - Denies credential reads and unapproved egress *inside the syscall*.
  - The kernel only enforces maps that `checkpointd` fills.
- **Control plane** (`src/control_plane`, `/v1/cp`):
  - The persistent AI Risk DB (SQLite → Postgres), mapped to OWASP LLM Top 10 and MITRE ATLAS.
  - Agent enrollment, heartbeat and telemetry.
  - Content pipeline: snapshot → quality gate → Ed25519 signature → CANARY/EARLY/BROAD/GA rings → auto-rollback.
  - Learning loop from the gateway into the persistent DB.
- **Portal** (`/portal`): overview, detections with process lineage, endpoints, Risk DB, releases, deploy, audit.

**Results (measured on the MacBook)**
- A hijacked agent's `curl … ~/.ssh/id_rsa` command was killed before the exfiltration step ran.
- Poisoned PDF and README were sanitized; the clean file was untouched; normal commands were allowed.
- A Korean zero-day learned at the gateway reached the CANARY endpoint as signed release v2 in about 5 s (gate: 88.6% recall, 0/40 false positives). BROAD stayed on v1 until promoted.
- Tampered bundles were rejected. A release that fired on benign text failed the gate. Two failing canaries triggered auto-rollback.
- Tests: 23 new; full suite 81 passed, 2 xfailed.

**Bugs found while building**
- **fork/exec race in the polling sensor.** A process seen between `fork` and `exec` still carries its parent's command line. Fix: young AI-lineage processes are re-judged when their command line changes. This is also the argument for kernel hooks, which have no such gap.
- **The learning loop dropped confirmations.** A pending entry confirmed at the gateway stayed pending in the persistent DB. Fix: the gateway now reports confirmed texts too, and the DB promotes them.

**Open questions / next steps**
- Compile and test the BPF program on a real Linux kernel (≥ 5.7, `lsm=…,bpf`).
- macOS Endpoint Security entitlement (needed for pre-exec deny and the file-open hook on Mac).
- SSO/RBAC for the portal, Postgres + KMS signing key, and agent tamper protection.
- Rename "Falcon" (trademark) before any commercial use. This is still open from the previous entry.

---

## 2026-11-02: Linux kernel checkpoint verified in a real kernel; Windows agent, minifilter and CI

**Discussion:** "Is the code complete end to end?" The demo ran end to end, but the product did not: the BPF program had never been compiled, and there was no Windows agent or installer. Then: "make it and make the agent for windo[ws] machine as well."

**Linux kernel checkpoint: built and verified**
- **Where:** a Fedora 44 VM (Lima on the MacBook), kernel 6.19 arm64, btrfs root.
- **Results:**
  - The verifier accepts all 6 programs, and 8/8 live kernel tests pass.
  - Full suite as root, with the program attached: 116 passed.
  - In the demo, a native agent that exfiltrated immediately was stopped in the kernel at `connect()`. The polling sensor never saw it.
- **CI:** GitHub's Ubuntu 24.04 runner (kernel 7.0, x86_64) also builds it. The kernel tests skip there because Ubuntu does not enable the BPF LSM.
- **Bugs only a real kernel showed:**
  - **Compile errors.** A map named `config` clashed with a name in the generated kernel headers (renamed `cp_config`); `bpf_endian.h` was missing.
  - **Stale pinned maps.** Pins left by a previous run swallowed the protection rules. Fix: the loader clears the pins and waits until the program is attached.
  - **btrfs device numbers.** `stat().st_dev` is not the kernel's `i_sb->s_dev`, so files in home folders were not protected. Fix: take the device from `/proc/self/mountinfo`.
  - **Registration race.** An agent that acts the moment it starts beat the user-space registration. Fix: the kernel now recognises AI agents by name at exec. The Windows driver does the same at process creation.
  - **Leaked loaders.** Loader processes outlived tests that died. Fix: `PR_SET_PDEATHSIG`.

**Windows: agent verified in CI, driver built**
- **Agent:**
  - Windows command forms: `%USERPROFILE%`, `$env:USERPROFILE`, `curl.exe`, PowerShell download cmdlets.
  - Destructive commands are blocked: shadow-copy deletion, `wbadmin`, `bcdedit`, `cipher /w`.
  - Download-or-execute abuse of `certutil`, `bitsadmin`, `mshta`, `regsvr32` and `rundll32` raises an alert.
  - Running as SYSTEM, it protects every user's credential stores, including Credential Manager, DPAPI keys and browser passwords.
- **Installer:** `install.ps1` registers a SYSTEM scheduled task that starts at boot and restarts if it exits.
- **Minifilter (`checkpoint.sys`):**
  - Tracks AI lineage at process creation.
  - Asks `checkpointd` before an AI-lineage process starts. A block verdict fails the creation; with no answer in 250 ms, the process is allowed (fail open).
  - Denies AI-lineage opens of credential paths in `IRP_MJ_CREATE`.
- **CI results:**
  - The agent installed as SYSTEM, enrolled, sanitized the poisoned README and PDF, and killed the hijacked agent's `curl.exe` exfiltration before it ran. The control plane received the events with process lineage.
  - The driver compiles with `/W4 /WX`, passes InfVerif and Inf2Cat, and has `/INTEGRITYCHECK` set.
- **Bugs CI found:**
  - **Service crash on start (product bug).** The SYSTEM service crashed on start because Python read the Risk DB seed (Korean text) in the Windows ANSI code page. Tests had hidden this with `PYTHONUTF8=1`. Fix: explicit UTF-8 for all text I/O, and the service also runs with `-X utf8`.
  - **Quarantine collision (product bug).** Quarantining the same file twice failed on Windows, because rename never overwrites.
  - **Driver packaging (build setup).** The WDK needed 64-bit MSBuild and `FilesToPackage`.

**Open questions / next steps**
- Load the driver on a Windows VM with test signing on. For production: attestation signing and an altitude assigned by Microsoft (385210 is a placeholder).
- Kernel egress: a WFP callout on Windows; IPv6 in the Linux `connect()` hook.
- Tamper protection for the Windows agent (protected service).
- Linux fleets on Ubuntu need `lsm=…,bpf` on the kernel command line, or they run on the user-space sensors only.

---

## 2026-11-02: Where eBPF and the Windows driver stand; push target; docs, deck and spec brought up to date

**Discussion:** "Is eBPF used in the code?" · "Does the Windows agent read at the OS kernel level?" · "But the code is there, right?" · "Push the code to ai-edr-guardrail, always." · "Update architecture.md, the ppt and the enterprise AI security guardrail spec with the latest details."

**Key points**
- **eBPF is used on Linux only.** The agent attaches it automatically when four things hold: it runs as root, the loader is built, `bpftool` is installed, and `bpf` is in the active LSM list. Otherwise it falls back to user-space polling. The program has 6 kernel hooks (3 LSM hooks, 3 tracepoints) and 6 maps. The kernel enforces; user space detects.
- **The Windows agent tested in CI runs in user space today.** The kernel driver code is complete, in both repos, and builds clean in CI, but it has never been loaded.
  - Windows only loads signed drivers. Testing needs test signing and a reboot; production needs attestation signing and an altitude assigned by Microsoft.
  - Once the driver is loaded, the agent connects to it automatically.
  - A Windows VM on an Apple Silicon Mac is ARM64, and the driver is built for x64 only, so testing there needs an ARM64 build.

**Decisions**
- **Push target:** from now on every push goes to both Raj-588/ai-edr-guardrail `main` and Raj-588/sdsi-demo `Round_3_CheckPoint_Zero_AI_EDR`, fast-forward only. Commits that touch `.github/workflows/` go over SSH, because the gh CLI token lacks the `workflow` scope.
- **Executive deck** (`presentation/AI-EDR_Guardrail_Executive_28Oct.pptx`) is now 26 slides.
  - New slides 19–22: the endpoint agent; the kernel checkpoint by OS, with honest status; real output from the Windows CI run and the Linux kernel; the fleet control plane.
  - Updated: slide 2 mentions the endpoint agent, slide 17 shows 120 tests, and slides 23–25 no longer call the endpoint agent future work.
  - `update_exec_deck.py` must not be re-run: it rebuilds from the 28 Oct original and would drop the new slides.
- **`enterprise_ai_security_guardrail_specification.md`** now records what was built: models, thresholds, the 5 integration modes, the schema, the repo layout, the endpoint agent, the control plane, results and limits. The original Gemini build prompts are kept as history.
- **`architecture.md`:** §19 is marked as the design. §20.1 (kernel checkpoints by OS) and §20.2 (CI) were added. The README limits line no longer says the BPF code is untested.

**Open questions / next steps**
- An ARM64 build of the Windows driver and a test-signing script, to load it in a Windows VM on the Mac.
- The older generated deck (`presentation/AI-EDR_Guardrail.pptx`) still shows the 28 Oct content.

---

## 2026-11-02: Agent-first, not agent-only: what the enterprise product is

**Discussion:** "We will be making agents only, right, for the enterprise solution?"

**Key points**
- **The endpoint agent (CheckPoint Zero) is the core and the differentiator.** AI agents act: they run commands and read keys. Only something on the machine can stop that, and it can't be bypassed by unsetting a variable or switching tools. It also finds shadow AI and local models.
- **The agent sees actions, not the conversation.** Prompt injection lives in the text sent to the model, which travels inside TLS. Only the gateway, IDE hooks and browser extension see that text. The agent catches the consequence (the exfiltration command) and poisoned files on disk.
- **Some AI has no endpoint at all.** Server and cloud AI (FabriX workflows, AI Pro backends, RAG pipelines, MCP servers) is protected through the gateway and hook API.
- **Some devices can't take a kernel agent:** phones, BYOD and contractor machines. Driver signing and Apple's entitlement also take months, while a gateway deploys in days.
- **The current pilot ask runs on the gateway and hook API,** not the agent: one FabriX workflow and one AI Pro team, audit-only.

**Decision (recommended)**
- **One platform:** one engine, Risk DB and console behind every sensor.
- **Two products:**
  - **CheckPoint Zero Endpoint,** priced per device. Lands in R&D, where coding agents run.
  - **AI-EDR Gateway,** priced per gateway or server. Protects FabriX, AI Pro and RAG.
- **Included with both:** the browser extension, the IDE hooks and the control plane.
- This matches the go-to-market draft above: a per-endpoint add-on plus a gateway tier.

**Open questions**
- Product names (the "Falcon" trademark issue is still open).
- Whether the pilot adds a small endpoint cohort (R&D laptops with coding agents) next to the FabriX and AI Pro gateway pilot.

## 2026-11-03: MD brief: 8 slides, agent-led, a 60-day ask

**Discussion:** "Make a ppt of 8 pages apart from the first page, and include: 1. the major solution is the agent, right? What we are solving. 2. Do not commit latency for now; ask for 60 days and one security member. 3. What is in scope and out of scope, e.g. will it cover image and voice injection? Keep it very concise, as it will be shown to the MD." Later: "Update the ask: add a subscription to an LLM model for fast delivery."

**Key points**
- **New deck:** `AI-EDR_Guardrail_MD_Brief_03Nov.pptx` (in `presentation/` and the repo root), built by `presentation/build_md_deck.py`. It reuses the executive deck's cover (with the team block), theme and icons, followed by 8 slides: problem, gap, the agent, how it works, proof, scope, 60-day pilot, ask.
- **The agent leads.** The CheckPoint Zero agent is shown as the major solution. The gateway appears as cover for AI with no device to install on: FabriX, AI Pro and RAG.
- **No latency figure** appears on any slide or in the notes. The pilot measures detection, false alarms and speed on real use, and reports them on day 60.
- **Scope:**
  - In: text-based injection (prompts, PDF/Word, code, web pages, RAG) and agent actions (commands, file access, network).
  - Out of this pilot: image-based injection (next phase, with OCR), voice and audio (later), checking the AI's answers (next phase), mobile phones (later).
  - The code has no OCR or audio path today.
- **Proof without rates:** the deck shows verified results per OS and the test count. The 70%/33% held-out detection rates are left for the pilot to measure on Samsung data.
- **Executive deck fix:** 5 slides (the demo video and the 4 endpoint-agent slides) were outside any PowerPoint section. They are now in sections.

**Decisions**
- **The pilot ask changes** from 30 days, gateway only (executive deck), to **60 days, one security team member and an LLM subscription for the team** (so the team builds, tests and delivers faster).
- **Pilot scope in the deck:**
  - Agent on one R&D team's laptops, plus the gateway on one FabriX workflow and one AI Pro team.
  - Days 1–15 monitor only; days 16–45 tune and test with the security member; days 46–60 blocking for a small group, then report.
  - This answers the 2 Nov open question: the pilot adds an endpoint cohort.

**Open questions**
- Is the security team member full-time or part-time?
- Which LLM and plan, and how many seats, for the subscription?
- How many laptops are in the R&D cohort?
- Voice and audio injection has no roadmap item yet; the slide says "later".
- The executive deck still says "30-day pilot" and shows latency figures (30 days: slides 2 and 25; latency: slides 2, 7 and 17). Align it if both decks will be shown.
