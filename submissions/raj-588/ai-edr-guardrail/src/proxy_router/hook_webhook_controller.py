"""Mode 2 — Out-of-Band Pre-LLM Hook API (POST /v1/ai-edr/inspect) + admin/analyst endpoints.

Callers (FabriX workflow nodes, AI Pro pipelines, IDE hooks) get a Verdict back and dispatch
to the model themselves. The gateway never calls an LLM from these endpoints.
"""
from __future__ import annotations

import asyncio
import base64
import os
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..adapters import ADAPTERS
from ..demo_console.events import bus, to_sse
from ..schemas.canonical import (
    ActorContext,
    CanonicalAIEDRRequest,
    IndirectAttachment,
    InputVectors,
    InspectionStage,
    PolicyMode,
    PolicyProfile,
    ProposedToolCall,
    SegmentKind,
    SourcePlatform,
)
from ..settings import settings


def require_key(x_ai_edr_key: Optional[str] = Header(default=None)) -> None:
    if settings.api_key and x_ai_edr_key != settings.api_key:
        raise HTTPException(status_code=401, detail="invalid or missing X-AI-EDR-Key")


router = APIRouter(prefix="/v1/ai-edr", dependencies=[Depends(require_key)])


class RawProviderInspect(BaseModel):
    """Inspect a raw provider payload without forwarding it (returns the sanitized payload if any)."""
    source_platform: SourcePlatform
    payload: dict[str, Any]
    path: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class SimpleAttachment(BaseModel):
    filename: str
    text: Optional[str] = None
    content_base64: Optional[str] = None
    mime_type: Optional[str] = None
    kind: SegmentKind = SegmentKind.FILE


class SimpleInspect(BaseModel):
    """Small request shape for IDE hooks and scripts."""
    platform: SourcePlatform = SourcePlatform.CLAUDE_IDE
    stage: InspectionStage = InspectionStage.PRE_LLM_DIRECT
    prompt: str = ""
    system: str = ""
    attachments: list[SimpleAttachment] = Field(default_factory=list)
    tool_calls: list[ProposedToolCall] = Field(default_factory=list)
    tenant_id: str = "default"
    user_id: str = "anonymous"
    session_id: Optional[str] = None
    client: str = "hook"
    mode: Optional[PolicyMode] = None


def _guard(request: Request):
    return request.app.state.guard


@router.post("/inspect")
async def inspect(request: Request):
    body = await request.json()
    guard = _guard(request)
    if "payload" in body and "source_platform" in body and "input_vectors" not in body:
        r = RawProviderInspect(**body)
        adapter = ADAPTERS[r.source_platform]
        canon = adapter.to_canonical(r.payload, r.headers, r.path)
        verdict = guard.inspect(canon, raw_payload=r.payload, adapter=adapter)
    else:
        canon = CanonicalAIEDRRequest(**body)
        verdict = guard.inspect(canon)
    return verdict.model_dump(mode="json")


@router.post("/inspect/simple")
async def inspect_simple(body: SimpleInspect, request: Request):
    actor = ActorContext(tenant_id=body.tenant_id, user_id=body.user_id, client_ide_or_app=body.client)
    if body.session_id:
        actor.session_id = body.session_id
    canon = CanonicalAIEDRRequest(
        source_platform=body.platform, inspection_stage=body.stage, actor_context=actor,
        input_vectors=InputVectors(
            direct_user_prompt=body.prompt, system_instructions=body.system,
            indirect_attachments=[IndirectAttachment(filename=a.filename, extracted_raw_text=a.text or "",
                                                     content_base64=a.content_base64,
                                                     mime_type=a.mime_type or "application/octet-stream" if a.content_base64 else (a.mime_type or "text/plain"),
                                                     kind=a.kind, source_path=f"/attachments/{i}")
                                  for i, a in enumerate(body.attachments)],
            proposed_tool_calls=body.tool_calls),
        policy_profile=PolicyProfile(mode=body.mode))
    v = _guard(request).inspect(canon)
    out = v.model_dump(mode="json")
    out["sanitized_attachments"] = {e.source_path: e.sanitized_text for e in v.sanitization}
    return out


@router.post("/scan-file")
async def scan_file_endpoint(request: Request, filename: str, tenant_id: str = "default", platform: SourcePlatform = SourcePlatform.CLAUDE_IDE):
    """Upload raw bytes of a file (e.g. curl --data-binary @resume.pdf) and get a verdict."""
    data = await request.body()
    body = SimpleInspect(platform=platform, stage=InspectionStage.PRE_LLM_INDIRECT_FILE, tenant_id=tenant_id,
                         attachments=[SimpleAttachment(filename=filename, content_base64=base64.b64encode(data).decode())])
    return await inspect_simple(body, request)


# ---------------------------------------------------------------------------
# Analyst / admin
# ---------------------------------------------------------------------------

@router.get("/quarantine")
async def list_quarantine(request: Request, limit: int = 50):
    return _guard(request).vault.list(limit)


@router.get("/quarantine/{qid}")
async def get_quarantine(qid: str, request: Request):
    rec = _guard(request).vault.get(qid)
    if not rec:
        raise HTTPException(404, "not found")
    return rec


@router.post("/quarantine/{qid}/status")
async def set_quarantine_status(qid: str, request: Request, status: str = "RELEASED"):
    if status not in ("RELEASED", "CONFIRMED_MALICIOUS", "QUARANTINED"):
        raise HTTPException(400, "bad status")
    if not _guard(request).vault.set_status(qid, status):
        raise HTTPException(404, "not found")
    return {"quarantine_id": qid, "status": status}


@router.get("/risk-db")
async def risk_db(request: Request):
    g = _guard(request)
    return {"signatures": g.signatures.stats(), "vectors": g.vectors.stats(),
            "falcon_promotions": g.feed.promotions[-50:]}


@router.post("/risk-db/revert-falcon-loop")
async def revert_falcon(request: Request):
    g = _guard(request)
    return {"signatures_removed": g.signatures.remove_source("FALCON_LOOP"),
            "vectors_reverted": g.vectors.revert_source("FALCON_LOOP")}


@router.get("/process-tree/{session_id}")
async def process_tree(session_id: str, request: Request):
    return _guard(request).engine.process_tree.chain(session_id)


@router.get("/stats")
async def stats(request: Request):
    g = _guard(request)
    return {**g.stats, "events": bus.counters, "upstream_mode": settings.upstream_mode,
            "risk_db": {"signatures": g.signatures.stats(), "vectors": g.vectors.stats()}}


@router.get("/events/recent")
async def recent_events(n: int = 100, kind: Optional[str] = None):
    return bus.recent(n, kind)


@router.get("/events")
async def events(request: Request):
    q = bus.subscribe()

    async def gen():
        try:
            yield "retry: 2000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=15)
                    yield to_sse(evt)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            bus.unsubscribe(q)
    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/demo-files")
async def demo_files():
    from ..settings import ROOT
    d = ROOT / "demo" / "files"
    return sorted(os.listdir(d)) if d.exists() else []


@router.get("/demo-files/{name}")
async def demo_file(name: str):
    from ..settings import ROOT
    p = (ROOT / "demo" / "files" / name).resolve()
    if p.parent != (ROOT / "demo" / "files").resolve() or not p.exists():
        raise HTTPException(404, "not found")
    return {"filename": name, "content_base64": base64.b64encode(p.read_bytes()).decode()}
