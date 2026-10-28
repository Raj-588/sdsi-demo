"""Samsung FabriX adapter: /v1/fabrix/*

FabriX's wire format is not public, so this adapter is driven by `platform_field_maps.SAMSUNG_FABRIX`
in config/ai_edr_policies.yaml (where the query, prompt template, RAG chunks, history and agent
actions live). Enterprise headers X-FabriX-Tenant-Id / X-FabriX-Trace-Id and the SSO bearer
token are preserved and forwarded untouched.
"""
from __future__ import annotations

import copy
import json
from typing import Any, Mapping

from ..schemas.canonical import (
    CanonicalAIEDRRequest,
    IndirectAttachment,
    InputVectors,
    InspectionStage,
    ProposedToolCall,
    SegmentKind,
    SourcePlatform,
    Verdict,
)
from ..settings import policy_store, settings
from .base_adapter import BaseAdapter, get_path, get_ptr, set_ptr, text_of


class SamsungFabriXAdapter(BaseAdapter):
    platform = SourcePlatform.SAMSUNG_FABRIX
    prefix = "/v1/fabrix"
    doc_kind = SegmentKind.RAG_CHUNK

    def _field_map(self) -> dict:
        return policy_store.field_map(self.platform.value)

    def to_canonical(self, raw: dict, headers: Mapping[str, str], path: str = "") -> CanonicalAIEDRRequest:
        fm = self._field_map()
        iv = InputVectors()
        for p in fm.get("user_prompt", []):
            val, pointer = get_path(raw, p)
            if val:
                iv.direct_user_prompt = text_of(val)
                iv.user_prompt_source_path = pointer
                break
        systems = []
        for p in fm.get("system", []):
            val, _ = get_path(raw, p)
            if val:
                systems.append(text_of(val))
        iv.system_instructions = "\n".join(systems)

        text_key = fm.get("document_text_key", "content")
        name_key = fm.get("document_name_key", "title")
        for p in fm.get("documents", []):
            docs, pointer = get_path(raw, p)
            if not isinstance(docs, list):
                continue
            for i, d in enumerate(docs):
                if isinstance(d, str):
                    iv.indirect_attachments.append(IndirectAttachment(
                        filename=f"{p}[{i}]", extracted_raw_text=d, kind=self.doc_kind, source_path=f"{pointer}/{i}"))
                elif isinstance(d, dict):
                    name = str(d.get(name_key) or f"{p}[{i}]")
                    if d.get("content_base64"):
                        iv.indirect_attachments.append(IndirectAttachment(
                            filename=name, content_base64=d["content_base64"], mime_type=d.get("mime_type", ""),
                            kind=SegmentKind.FILE, source_path=f"{pointer}/{i}"))
                    else:
                        iv.indirect_attachments.append(IndirectAttachment(
                            filename=name, extracted_raw_text=text_of(d.get(text_key, "")), kind=self.doc_kind,
                            mime_type=d.get("mime_type", ""), source_path=f"{pointer}/{i}/{text_key}"))
        for p in fm.get("diff", []):
            val, pointer = get_path(raw, p)
            if isinstance(val, str) and val:
                iv.indirect_attachments.append(IndirectAttachment(
                    filename="workspace.diff", extracted_raw_text=val, mime_type="text/x-source",
                    kind=SegmentKind.FILE, source_path=pointer))
        for p in fm.get("tool_calls", []):
            calls, pointer = get_path(raw, p)
            for i, c in enumerate(calls or []):
                if isinstance(c, dict):
                    args = c.get("arguments") or c.get("args") or c.get("input") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except ValueError:
                            args = {"raw": args}
                    iv.proposed_tool_calls.append(ProposedToolCall(name=c.get("name") or c.get("tool", "tool"),
                                                                   arguments=args, source_path=f"{pointer}/{i}"))

        if iv.proposed_tool_calls:
            stage = InspectionStage.PRE_TOOL_EXECUTION
        elif any(a.kind == SegmentKind.RAG_CHUNK for a in iv.indirect_attachments):
            stage = InspectionStage.PRE_RAG_CHUNK if not iv.direct_user_prompt else InspectionStage.PRE_LLM_INDIRECT_FILE
        elif iv.indirect_attachments:
            stage = InspectionStage.PRE_LLM_INDIRECT_FILE
        else:
            stage = InspectionStage.PRE_LLM_DIRECT
        return CanonicalAIEDRRequest(source_platform=self.platform, inspection_stage=stage,
                                     actor_context=self.actor(headers, raw), input_vectors=iv)

    def actor(self, headers: Mapping[str, str], raw: dict | None = None):
        a = super().actor(headers, raw)
        h = {k.lower(): v for k, v in headers.items()}
        fm = self._field_map()
        tenant_h = fm.get("tenant_header", "").lower()
        if tenant_h and h.get(tenant_h) and not h.get(settings.tenant_header.lower()):
            a.tenant_id = h[tenant_h]
        trace_h = fm.get("trace_header", "").lower()
        if trace_h and h.get(trace_h) and not h.get("x-ai-edr-session"):
            a.session_id = h[trace_h]
        if raw and raw.get("user_id"):
            a.user_id = str(raw["user_id"])
        a.client_ide_or_app = h.get("x-ai-edr-client", self.platform.value.lower())
        return a

    def text_block(self, text: str) -> Any:
        return text

    def apply_sanitization(self, raw: dict, edits) -> dict:
        out = copy.deepcopy(raw)
        text_key = self._field_map().get("document_text_key", "content")
        for e in edits:
            if not e.source_path:
                continue
            try:
                current = get_ptr(out, e.source_path)
            except (KeyError, IndexError, ValueError, TypeError):
                continue
            if isinstance(current, dict):   # binary document -> replace with its cleaned text
                new = {k: v for k, v in current.items() if k not in ("content_base64", "mime_type")}
                new[text_key] = e.sanitized_text
                set_ptr(out, e.source_path, new)
            else:
                set_ptr(out, e.source_path, e.sanitized_text)
        return out

    def block_response(self, verdict: Verdict) -> tuple[int, dict]:
        return 403, {"result": "BLOCKED", "code": "AI_EDR_BLOCKED", "message": self.blocked_message(verdict),
                     "quarantine_id": verdict.quarantine_id, "severity": verdict.severity.value,
                     "categories": sorted({f.category for f in verdict.findings})}

    def upstream_base(self) -> str:
        return settings.fabrix_base

    def upstream_url(self, path: str, query: str = "") -> str:
        rest = path[len(self.prefix):] if path.startswith(self.prefix) else path
        return f"{self.upstream_base().rstrip('/')}{rest}" + (f"?{query}" if query else "")
