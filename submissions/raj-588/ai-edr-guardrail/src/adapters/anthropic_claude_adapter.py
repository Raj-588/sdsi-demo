"""Anthropic Claude & Claude IDE adapter: /v1/messages (system, messages, document, tool_use, tool_result).

Also used when Claude Code (or any Anthropic-SDK app) runs with ANTHROPIC_BASE_URL pointed at the gateway.
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping

from ..schemas.canonical import (
    CanonicalAIEDRRequest,
    IndirectAttachment,
    InputVectors,
    InspectionStage,
    SegmentKind,
    SourcePlatform,
    Verdict,
)
from ..settings import settings
from .base_adapter import BaseAdapter, last_index, ptr, text_of


class AnthropicClaudeAdapter(BaseAdapter):
    platform = SourcePlatform.CLAUDE_IDE

    def to_canonical(self, raw: dict, headers: Mapping[str, str], path: str = "") -> CanonicalAIEDRRequest:
        iv = InputVectors()
        system = raw.get("system")
        iv.system_instructions = system if isinstance(system, str) else text_of(system or [])

        messages = raw.get("messages") or []
        start = last_index(messages, lambda m: isinstance(m, dict) and m.get("role") == "assistant") + 1
        prompts: list[str] = []
        for i in range(start, len(messages)):
            m = messages[i]
            if not isinstance(m, dict) or m.get("role") != "user":
                continue
            content = m.get("content")
            if isinstance(content, str):
                prompts.append(content)
                iv.user_prompt_source_path = ptr("messages", i, "content")
                continue
            for j, block in enumerate(content or []):
                self._collect_block(block, ("messages", i, "content", j), prompts, iv)

        iv.direct_user_prompt = "\n".join(p for p in prompts if p)
        stage = (InspectionStage.PRE_LLM_INDIRECT_FILE if iv.indirect_attachments else InspectionStage.PRE_LLM_DIRECT)

        actor = self.actor(headers, raw)
        h = {k.lower(): v for k, v in headers.items()}
        platform = self.platform
        if "antigravity" in (h.get("x-ai-edr-client", "") + h.get("user-agent", "")).lower():
            platform = SourcePlatform.ANTIGRAVITY_IDE
        meta_user = (raw.get("metadata") or {}).get("user_id")
        if meta_user and not h.get("x-ai-edr-session"):
            actor.session_id = "sess_" + hashlib.sha1(str(meta_user).encode()).hexdigest()[:12]
        return CanonicalAIEDRRequest(source_platform=platform, inspection_stage=stage, actor_context=actor,
                                     input_vectors=iv)

    def _collect_block(self, block: dict, loc: tuple, prompts: list[str], iv: InputVectors) -> None:
        t = block.get("type")
        if t == "text":
            prompts.append(block.get("text", ""))
        elif t == "document":
            src = block.get("source") or {}
            name = block.get("title") or f"document_{loc[1]}_{loc[3]}"
            if src.get("type") == "base64":
                iv.indirect_attachments.append(IndirectAttachment(
                    filename=name if "." in name else f"{name}.pdf", mime_type=src.get("media_type", "application/pdf"),
                    content_base64=src.get("data"), source_path=ptr(*loc)))
            elif src.get("type") == "text":
                iv.indirect_attachments.append(IndirectAttachment(
                    filename=name, extracted_raw_text=src.get("data", ""), source_path=ptr(*loc, "source", "data")))
        elif t == "tool_result":
            content = block.get("content")
            label = f"tool_result:{block.get('tool_use_id', '')[-8:]}"
            if isinstance(content, str):
                iv.indirect_attachments.append(IndirectAttachment(
                    filename=label, extracted_raw_text=content, kind=SegmentKind.TOOL_RESULT,
                    source_path=ptr(*loc, "content")))
            elif isinstance(content, list):
                for k, sub in enumerate(content):
                    if sub.get("type") == "text":
                        iv.indirect_attachments.append(IndirectAttachment(
                            filename=label, extracted_raw_text=sub.get("text", ""), kind=SegmentKind.TOOL_RESULT,
                            source_path=ptr(*loc, "content", k, "text")))
                    elif sub.get("type") == "document":
                        self._collect_block(sub, (*loc, "content", k), prompts, iv)

    def text_block(self, text: str) -> Any:
        return {"type": "text", "text": text}

    def block_response(self, verdict: Verdict) -> tuple[int, dict]:
        return 400, {"type": "error", "error": {"type": "invalid_request_error", "message": self.blocked_message(verdict)},
                     "ai_edr": {"quarantine_id": verdict.quarantine_id, "severity": verdict.severity.value}}

    def upstream_url(self, path: str, query: str = "") -> str:
        return f"{settings.anthropic_base}{path}" + (f"?{query}" if query else "")
