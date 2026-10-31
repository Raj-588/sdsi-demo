"""AI-EDR Inline Guardrail Platform — FastAPI entrypoint.

Mode 1  Universal reverse-proxy gateway (drop-in base_url):
          POST /v1/chat/completions, /v1/responses                 OpenAI / ChatGPT
          POST /v1/messages (+ /v1/messages/count_tokens)           Anthropic Claude, Claude Code, IDEs
          POST /v1beta/models/{model}:generateContent|stream...     Google Gemini
          POST /v1/fabrix/{path}                                    Samsung FabriX
          POST /v1/aipro/{path}                                     Samsung AI Pro
Mode 2  Out-of-band hook API: POST /v1/ai-edr/inspect (see proxy_router/hook_webhook_controller.py)
Fleet   /portal (endpoint fleet + Risk DB + content releases), /v1/cp/... (control plane for checkpointd agents)
Demo    /console (live SOC view), /mock/... (the unprotected vulnerable mock LLM)

Run:  uvicorn src.main:app --port 8080
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response

from .adapters import ADAPTERS
from .control_plane.api import ControlPlane, agent_router, portal_router
from .ai_edr_guard.pipeline_orchestrator import AIEDRGuard
from .mock_llm import vulnerable_brain as mock
from .proxy_router import upstream_dispatcher
from .proxy_router.hook_webhook_controller import router as hook_router
from .schemas.canonical import SourcePlatform, VerdictType
from .settings import settings

CONSOLE = Path(__file__).resolve().parent / "demo_console" / "console.html"
PORTAL = Path(__file__).resolve().parent / "portal" / "portal.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.guard = AIEDRGuard()
    app.state.cp = ControlPlane()
    # Warm up parsers / classifier so the first real request is not slow.
    import pymupdf

    from .collectors.indirect_file_scanner import scan_file
    doc = pymupdf.open()
    doc.new_page().insert_text((50, 50), "warm up")
    scan_file("warmup.pdf", data=doc.tobytes())
    app.state.guard.engine.classifier.predict("warm up")
    yield
    if upstream_dispatcher._client is not None:
        await upstream_dispatcher._client.aclose()


app = FastAPI(title="AI-EDR Inline Guardrail Platform", version="1.0.0", lifespan=lifespan)
app.include_router(hook_router)
app.include_router(agent_router)
app.include_router(portal_router)


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse("/console")


@app.get("/console", include_in_schema=False)
async def console():
    return FileResponse(CONSOLE)


@app.get("/portal", include_in_schema=False)
async def portal():
    return FileResponse(PORTAL)


@app.get("/extension-test", include_in_schema=False)
async def extension_test():
    """Stand-in chat page used to test the browser extension without logging in to claude.ai / gemini."""
    return FileResponse(CONSOLE.parent / "extension_test.html")


@app.post("/extension-test/{rest:path}", include_in_schema=False)
async def extension_test_send(rest: str):
    return {"ok": True}


@app.get("/healthz")
async def healthz(request: Request):
    g = request.app.state.guard
    return {"status": "ok", "upstream_mode": settings.upstream_mode, "classifier": getattr(g.engine.classifier, "name", "?"),
            "embedder": g.vectors.embedder.name}


# ---------------------------------------------------------------------------
# Mode 1: inline reverse proxy
# ---------------------------------------------------------------------------

async def _guarded(request: Request, platform: SourcePlatform, inspect: bool = True) -> Response:
    raw_body = await request.body()
    if len(raw_body) > settings.max_body_bytes:
        return JSONResponse({"error": {"message": "payload too large for AI-EDR inspection"}}, status_code=413)
    try:
        payload = json.loads(raw_body or b"{}")
    except ValueError:
        return JSONResponse({"error": {"message": "invalid JSON"}}, status_code=400)
    adapter = ADAPTERS[platform]
    path = request.url.path
    headers = dict(request.headers)
    if inspect:
        canon = adapter.to_canonical(payload, headers, path)
        verdict = request.app.state.guard.inspect(canon, raw_payload=payload, adapter=adapter)
        if verdict.verdict == VerdictType.BLOCKED:
            status, body = adapter.block_response(verdict)
            return JSONResponse(body, status_code=status, headers={"X-AI-EDR-Verdict": "BLOCKED",
                                                                   "X-AI-EDR-Quarantine-Id": verdict.quarantine_id or ""})
        if verdict.verdict == VerdictType.ALLOWED_SANITIZED and verdict.sanitized_payload is not None:
            payload = verdict.sanitized_payload
        resp = await upstream_dispatcher.forward(adapter, path, request.url.query, headers, payload)
        resp.headers["X-AI-EDR-Verdict"] = verdict.verdict.value
        resp.headers["X-AI-EDR-Risk"] = str(verdict.risk_score)
        return resp
    return await upstream_dispatcher.forward(adapter, path, request.url.query, headers, payload)


@app.post("/v1/chat/completions")
@app.post("/v1/responses")
async def openai_proxy(request: Request):
    return await _guarded(request, SourcePlatform.OPENAI)


@app.post("/v1/messages")
async def anthropic_proxy(request: Request):
    return await _guarded(request, SourcePlatform.CLAUDE_IDE)


@app.post("/v1/messages/count_tokens")
async def anthropic_count_tokens(request: Request):
    return await _guarded(request, SourcePlatform.CLAUDE_IDE, inspect=False)


@app.post("/v1beta/models/{model_action:path}")
@app.post("/v1/models/{model_action:path}")
async def gemini_proxy(model_action: str, request: Request):
    inspect = model_action.endswith(("generateContent", "streamGenerateContent"))
    return await _guarded(request, SourcePlatform.GEMINI, inspect=inspect)


@app.post("/v1/fabrix/{rest:path}")
async def fabrix_proxy(rest: str, request: Request):
    return await _guarded(request, SourcePlatform.SAMSUNG_FABRIX)


@app.post("/v1/aipro/{rest:path}")
async def aipro_proxy(rest: str, request: Request):
    return await _guarded(request, SourcePlatform.SAMSUNG_AIPRO)


@app.api_route("/v1/{rest:path}", methods=["GET", "POST", "DELETE", "HEAD"], include_in_schema=False)
@app.api_route("/api/{rest:path}", methods=["GET", "POST", "HEAD"], include_in_schema=False)
async def passthrough(rest: str, request: Request):
    """Other provider endpoints (model lists, files, batches, health probes) are forwarded without inspection."""
    h = {k.lower() for k in request.headers.keys()}
    anthropic = "anthropic-version" in h or "x-api-key" in h or request.url.path.startswith("/api/")
    platform = SourcePlatform.CLAUDE_IDE if anthropic else SourcePlatform.OPENAI
    body = await request.body()
    return await upstream_dispatcher.forward(ADAPTERS[platform], request.url.path, request.url.query,
                                             dict(request.headers), None, raw_body=body, method=request.method)


# ---------------------------------------------------------------------------
# Unprotected mock LLM (for the "without AI-EDR" side of the demo)
# ---------------------------------------------------------------------------

@app.post("/mock/{platform}/{rest:path}", tags=["mock"])
async def mock_llm(platform: str, rest: str, request: Request):
    payload = await request.json()
    mapping = {"openai": SourcePlatform.OPENAI, "anthropic": SourcePlatform.CLAUDE_IDE, "gemini": SourcePlatform.GEMINI,
               "fabrix": SourcePlatform.SAMSUNG_FABRIX, "aipro": SourcePlatform.SAMSUNG_AIPRO}
    if platform not in mapping:
        return JSONResponse({"error": "unknown mock platform"}, status_code=404)
    return upstream_dispatcher.mock_dispatch(mapping[platform], "/" + rest, payload)


@app.get("/mock/system-prompt", include_in_schema=False)
async def mock_system_prompt():
    return {"system_prompt": mock.FAKE_SYSTEM_PROMPT}
