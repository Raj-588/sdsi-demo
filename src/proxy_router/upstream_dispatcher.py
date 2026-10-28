"""Stage 4 — forwards Clean Safe Input to the AI Brain (OpenAI, Gemini, Claude, FabriX, AI Pro).

* real mode: streams the provider response straight back (SSE / chunked), auth headers untouched
* mock mode: answers from the built-in vulnerable mock LLM (offline demo)
Mode comes from AI_EDR_UPSTREAM_MODE or per request from the X-AI-EDR-Upstream header.
"""
from __future__ import annotations

import json
from typing import Mapping

import httpx
from fastapi.responses import JSONResponse, Response, StreamingResponse

from ..mock_llm import vulnerable_brain as mock
from ..schemas.canonical import SourcePlatform
from ..settings import settings

HOP_BY_HOP = {"host", "content-length", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade"}
STRIP_REQUEST = HOP_BY_HOP | {"x-ai-edr-upstream", "x-ai-edr-key", "accept-encoding"}
STRIP_RESPONSE = HOP_BY_HOP | {"content-encoding"}

_client: httpx.AsyncClient | None = None


def client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=15.0), follow_redirects=False)
    return _client


def upstream_mode(headers: Mapping[str, str]) -> str:
    h = {k.lower(): v for k, v in headers.items()}
    return h.get("x-ai-edr-upstream", settings.upstream_mode).lower()


def mock_dispatch(platform: SourcePlatform, path: str, payload: dict) -> Response:
    streaming = bool(payload.get("stream")) or "streamGenerateContent" in path
    if platform in (SourcePlatform.CLAUDE_IDE, SourcePlatform.ANTIGRAVITY_IDE):
        if path.endswith("/count_tokens"):
            return JSONResponse({"input_tokens": len(json.dumps(payload)) // 4})
        if streaming:
            return StreamingResponse(mock.anthropic_stream(payload), media_type="text/event-stream")
        return JSONResponse(mock.anthropic_response(payload))
    if platform == SourcePlatform.OPENAI:
        if path.endswith("/responses"):
            return JSONResponse(mock.openai_responses_api(payload))
        if streaming:
            return StreamingResponse(mock.openai_stream(payload), media_type="text/event-stream")
        return JSONResponse(mock.openai_response(payload))
    if platform == SourcePlatform.GEMINI:
        if streaming:
            return StreamingResponse(mock.gemini_stream(payload), media_type="text/event-stream")
        return JSONResponse(mock.gemini_response(payload))
    if platform == SourcePlatform.SAMSUNG_FABRIX:
        return JSONResponse(mock.fabrix_response(payload))
    return JSONResponse(mock.aipro_response(payload))


async def forward(adapter, path: str, query: str, headers: Mapping[str, str], payload: dict | None,
                  raw_body: bytes | None = None, method: str = "POST") -> Response:
    if upstream_mode(headers) == "mock":
        return mock_dispatch(adapter.platform, path, payload or {})

    url = adapter.upstream_url(path, query)
    if url.startswith("/") or "://" not in url:
        return JSONResponse({"error": {"message": f"No upstream configured for {adapter.platform.value}. "
                                                  f"Set the AI_EDR_*_UPSTREAM env var or use X-AI-EDR-Upstream: mock."}},
                            status_code=502)
    fwd_headers = {k: v for k, v in headers.items() if k.lower() not in STRIP_REQUEST}
    body = json.dumps(payload).encode() if payload is not None else (raw_body or b"")
    if payload is not None:
        fwd_headers["content-type"] = "application/json"
    req = client().build_request(method, url, headers=fwd_headers, content=body)
    resp = await client().send(req, stream=True)
    out_headers = {k: v for k, v in resp.headers.items() if k.lower() not in STRIP_RESPONSE}

    async def body_iter():
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose()
    return StreamingResponse(body_iter(), status_code=resp.status_code, headers=out_headers,
                             media_type=resp.headers.get("content-type"))
