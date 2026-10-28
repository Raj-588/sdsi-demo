"""Google Gemini adapter: /v1beta/models/{model}:generateContent and :streamGenerateContent."""
from __future__ import annotations

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
from ..settings import settings
from .base_adapter import BaseAdapter, last_index, ptr, set_ptr, text_of


class GoogleGeminiAdapter(BaseAdapter):
    platform = SourcePlatform.GEMINI

    def to_canonical(self, raw: dict, headers: Mapping[str, str], path: str = "") -> CanonicalAIEDRRequest:
        iv = InputVectors()
        si = raw.get("systemInstruction") or raw.get("system_instruction")
        if si:
            iv.system_instructions = text_of((si or {}).get("parts", []))

        contents = raw.get("contents") or []
        start = last_index(contents, lambda c: isinstance(c, dict) and c.get("role") == "model") + 1
        prompts: list[str] = []
        for i in range(start, len(contents)):
            c = contents[i]
            for j, part in enumerate(c.get("parts") or []):
                if "text" in part:
                    prompts.append(part["text"])
                elif "inlineData" in part or "inline_data" in part:
                    d = part.get("inlineData") or part.get("inline_data")
                    iv.indirect_attachments.append(IndirectAttachment(
                        filename=d.get("displayName") or f"inline_{i}_{j}" + _ext(d.get("mimeType", "")),
                        mime_type=d.get("mimeType", "application/octet-stream"), content_base64=d.get("data"),
                        source_path=ptr("contents", i, "parts", j)))
                elif "functionResponse" in part:
                    fr = part["functionResponse"]
                    iv.indirect_attachments.append(IndirectAttachment(
                        filename=f"function_response:{fr.get('name', '')}", kind=SegmentKind.TOOL_RESULT,
                        extracted_raw_text=json.dumps(fr.get("response", {}), ensure_ascii=False),
                        source_path=ptr("contents", i, "parts", j, "functionResponse", "response")))
                elif "functionCall" in part:
                    fc = part["functionCall"]
                    iv.proposed_tool_calls.append(ProposedToolCall(name=fc.get("name", ""), arguments=fc.get("args", {}),
                                                                   source_path=ptr("contents", i, "parts", j)))
        iv.direct_user_prompt = "\n".join(prompts)
        stage = InspectionStage.PRE_LLM_INDIRECT_FILE if iv.indirect_attachments else InspectionStage.PRE_LLM_DIRECT
        return CanonicalAIEDRRequest(source_platform=self.platform, inspection_stage=stage,
                                     actor_context=self.actor(headers, raw), input_vectors=iv)

    def text_block(self, text: str) -> Any:
        return {"text": text}

    def apply_sanitization(self, raw: dict, edits):
        out = super().apply_sanitization(raw, edits)
        # functionResponse.response must stay an object
        for e in edits:
            if e.source_path and e.source_path.endswith("/functionResponse/response"):
                set_ptr(out, e.source_path, {"content": e.sanitized_text})
        return out

    def block_response(self, verdict: Verdict) -> tuple[int, dict]:
        return 400, {"error": {"code": 400, "message": self.blocked_message(verdict), "status": "INVALID_ARGUMENT",
                               "details": [{"@type": "ai-edr/Blocked", "quarantineId": verdict.quarantine_id,
                                            "severity": verdict.severity.value}]}}

    def upstream_url(self, path: str, query: str = "") -> str:
        return f"{settings.gemini_base}{path}" + (f"?{query}" if query else "")


def _ext(mime: str) -> str:
    return {"application/pdf": ".pdf", "text/html": ".html", "text/markdown": ".md", "text/plain": ".txt"}.get(mime, "")
