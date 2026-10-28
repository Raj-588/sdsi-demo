"""OpenAI / ChatGPT adapter: /v1/chat/completions and /v1/responses."""
from __future__ import annotations

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


class OpenAIChatGPTAdapter(BaseAdapter):
    platform = SourcePlatform.OPENAI

    def to_canonical(self, raw: dict, headers: Mapping[str, str], path: str = "") -> CanonicalAIEDRRequest:
        iv = InputVectors()
        prompts: list[str] = []
        systems: list[str] = []

        if path.endswith("/responses") or "input" in raw and "messages" not in raw:
            if raw.get("instructions"):
                systems.append(raw["instructions"])
            items = raw.get("input")
            if isinstance(items, str):
                prompts.append(items)
                iv.user_prompt_source_path = ptr("input")
            else:
                self._collect_messages(items or [], "input", prompts, systems, iv)
        else:
            self._collect_messages(raw.get("messages") or [], "messages", prompts, systems, iv)

        iv.direct_user_prompt = "\n".join(p for p in prompts if p)
        iv.system_instructions = "\n".join(systems)
        stage = InspectionStage.PRE_LLM_INDIRECT_FILE if iv.indirect_attachments else InspectionStage.PRE_LLM_DIRECT
        actor = self.actor(headers, raw)
        if raw.get("user"):
            actor.user_id = str(raw["user"])
        return CanonicalAIEDRRequest(source_platform=self.platform, inspection_stage=stage, actor_context=actor,
                                     input_vectors=iv)

    def _collect_messages(self, messages: list, root: str, prompts, systems, iv: InputVectors) -> None:
        # Only the turns since the last assistant reply are new; older turns were inspected already.
        start = last_index(messages, lambda m: isinstance(m, dict) and m.get("role") == "assistant") + 1
        for i, m in enumerate(messages):
            if not isinstance(m, dict):
                continue
            role = m.get("role", "user")
            content = m.get("content")
            if role in ("system", "developer"):
                systems.append(text_of(content))
                continue
            if i < start:
                continue
            if role == "tool":
                if isinstance(content, str):
                    iv.indirect_attachments.append(IndirectAttachment(
                        filename=f"tool_result:{m.get('tool_call_id', i)}", extracted_raw_text=content,
                        kind=SegmentKind.TOOL_RESULT, source_path=ptr(root, i, "content")))
                continue
            if role != "user":
                continue
            if isinstance(content, str):
                prompts.append(content)
                iv.user_prompt_source_path = ptr(root, i, "content")
                continue
            for j, part in enumerate(content or []):
                t = part.get("type")
                if t in ("text", "input_text"):
                    prompts.append(part.get("text", ""))
                elif t in ("file", "input_file"):
                    f = part.get("file", part)
                    data = f.get("file_data", "")
                    iv.indirect_attachments.append(IndirectAttachment(
                        filename=f.get("filename", f"file_{i}_{j}"), content_base64=data or None,
                        mime_type=data.split(";")[0][5:] if data.startswith("data:") else "application/octet-stream",
                        source_path=ptr(root, i, "content", j)))

    def text_block(self, text: str) -> Any:
        return {"type": "text", "text": text}

    def block_response(self, verdict: Verdict) -> tuple[int, dict]:
        return 400, {"error": {"message": self.blocked_message(verdict), "type": "ai_edr_blocked",
                               "code": "prompt_injection_blocked", "param": None,
                               "quarantine_id": verdict.quarantine_id}}

    def upstream_url(self, path: str, query: str = "") -> str:
        return f"{settings.openai_base}{path}" + (f"?{query}" if query else "")
