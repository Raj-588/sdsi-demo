# Feasibility: AI-EDR with Samsung FabriX and Samsung AI Pro

**Bottom line:** integration is technically feasible for both platforms with the code in this repo. Two inputs from Samsung are still missing: the real request formats and the deployment environment. The FabriX and AI Pro request formats used in this repo are **assumptions**, because neither API is public. The adapters read them through a configurable field map, so plugging in the real format is a config change, not a code change.

## What was verified here

| Capability | Status | Evidence |
|---|---|---|
| FabriX adapter: prompt, prompt template, RAG chunks, agent actions, `X-FabriX-Tenant-Id` / `X-FabriX-Trace-Id` | ✅ working on the assumed format | `tests/test_samsung_fabrix_aipro_adapters.py` |
| FabriX guard node: blocks a Unicode-tag-smuggled RAG chunk before the LLM node | ✅ | `integrations/samsung/fabrix_workflow_guard.py` |
| Poisoned PDF sent to a FabriX agent → blocked and quarantined (BLOCK mode tenant) | ✅ | demo scenario 5 |
| AI Pro pre-send hook: blocks `SAMSUNG CONFIDENTIAL` source code and AWS keys (DLP) | ✅ | `integrations/samsung/aipro_presend_hook.py`, scenario 9 |
| Korean-language injections (signatures, IOAs, classifier) | ✅ on the test set; see limits below | `tests/test_direct_prompt_injection.py` |
| Real FabriX / AI Pro endpoints | ❌ not tested: no access | needs Samsung |

## Integration options

| Option | FabriX | AI Pro | Effort | Notes |
|---|---|---|---|---|
| **A. Hook API / guard node** (Mode 2) | Add one node before the LLM node that calls `POST /v1/ai-edr/inspect` | The IDE plugin calls the hook before sending (`aipro_presend_hook.py`) | Low | Recommended for the pilot. No change to the request path; can run in audit-only mode. |
| **B. Inline proxy** (Mode 1) | Point the FabriX LLM endpoint at `/v1/fabrix/*` | Point the plugin's API base at `/v1/aipro/*` | Low–Medium | Needs a configurable base URL. Streaming responses pass through unchanged. |
| **C. Network egress gateway** | Route all model egress through the gateway | Same | Medium | Strongest guarantee (no bypass). Needs network or platform team involvement. |

## What we need from Samsung

1. **Request and response formats** for FabriX agent/workflow calls and for the AI Pro plugin. With these, we update `platform_field_maps` in `config/ai_edr_policies.yaml`.
2. **Authentication:** how SSO bearer tokens are issued and validated (JWKS endpoint), and whether the gateway should validate them or only pass them through.
3. **Deployment target:** on-prem Kubernetes or an air-gapped environment. The model files ship inside the image, with no runtime download.
4. **Data policy:** whether quarantined payloads may be stored in full (`AI_EDR_STORE_PAYLOADS`) or only as hashes, and for how long.
5. **A sandbox tenant** plus one pilot team for each platform.

## Risks and limits (be explicit about these)

- **Classifier language coverage:** the bundled DeBERTa-v3 model is English-only. Korean text goes to the local classifier plus Korean signatures and IOAs, which generalizes less well (see `docs/BENCHMARK.md`). For production, evaluate a multilingual model such as Meta Prompt Guard 2 (license-gated) or train one on Samsung data.
- **False positives:** DeBERTa scores some benign phrasings very high (for example, "Please ignore the previous email…"). Start every tenant in `AUDIT_ONLY`, measure, then switch to `STRIP_AND_SANITIZE` or `BLOCK`.
- **Latency:** short prompts add tens of milliseconds on a CPU. Large documents can take hundreds of milliseconds and are cached by content hash. GPU or more CPU threads reduce this.
- **Coverage:** v1 inspects inputs only. Inspection of model output, and of injections hidden in images or OCR text, is on the roadmap.

## Proposed 30-day pilot

| Week | Activity | Exit criterion |
|---|---|---|
| 1 | Deploy the gateway in the sandbox; map the real FabriX and AI Pro formats | Adapter round-trip tests pass on real payloads |
| 2 | FabriX guard node and AI Pro pre-send hook in `AUDIT_ONLY` for one team each | Verdicts visible in the console; no change for users |
| 3 | Review the quarantine queue; tune thresholds and allow-lists; add Samsung-specific signatures | False-positive rate below the agreed target |
| 4 | Switch to `STRIP_AND_SANITIZE` for documents and `BLOCK` for DLP | Go/no-go for wider rollout |
