"""Stage 1 — Direct Attack Collector + segment builder.

Turns a CanonicalAIEDRRequest into trust-tagged Segments (architecture §4.2):
  SYSTEM        -> TRUSTED       (never scanned for injection, only for integrity)
  USER_PROMPT   -> SEMI_TRUSTED
  FILE / RAG / TOOL_RESULT / METADATA / hidden layers -> UNTRUSTED
"""
from __future__ import annotations

import json

from ..schemas.canonical import (
    CanonicalAIEDRRequest,
    InspectionStage,
    Segment,
    SegmentKind,
    Trust,
)
from .indirect_file_scanner import decode_b64, scan_file


def _seg_id(i: int) -> str:
    return f"seg_{i}"


def build_segments(req: CanonicalAIEDRRequest) -> list[Segment]:
    segs: list[Segment] = []
    iv = req.input_vectors

    def add(**kw) -> Segment:
        s = Segment(segment_id=_seg_id(len(segs)), **kw)
        segs.append(s)
        return s

    if iv.system_instructions.strip():
        add(kind=SegmentKind.SYSTEM, trust=Trust.TRUSTED, text=iv.system_instructions,
            raw_text=iv.system_instructions, label="system", source_path="system")

    if iv.direct_user_prompt.strip():
        # A user prompt arriving as a tool/agent hand-off is not the human typing it.
        trust = Trust.UNTRUSTED if req.inspection_stage == InspectionStage.PRE_RAG_CHUNK else Trust.SEMI_TRUSTED
        add(kind=SegmentKind.USER_PROMPT, trust=trust, text=iv.direct_user_prompt,
            raw_text=iv.direct_user_prompt, label="user_prompt", source_path=iv.user_prompt_source_path)

    for att in iv.indirect_attachments:
        data = decode_b64(att.content_base64) if att.content_base64 else None
        text = att.extracted_raw_text if not data else None
        scan = scan_file(att.filename, data=data, text=text, mime_type=att.mime_type)
        anomalies = list(dict.fromkeys(att.hidden_layer_anomalies + scan.anomalies))
        hidden = list(dict.fromkeys(scan.hidden_spans + att.suspicious_spans))
        body = scan.full_text or att.extracted_raw_text
        parent = add(kind=att.kind, trust=Trust.UNTRUSTED, text=body, raw_text=body, label=att.filename,
                     anomalies=anomalies, hidden_spans=hidden, source_path=att.source_path)
        # Hidden-layer text becomes its own segment so it is scored on its own, with the
        # FILE_TO_PROMPT_TRANSITION context, instead of being diluted by the visible document.
        if hidden:
            add(kind=SegmentKind.METADATA, trust=Trust.UNTRUSTED, text="\n".join(hidden),
                raw_text="\n".join(hidden), label=f"{att.filename}#hidden-layer",
                anomalies=anomalies, parent_id=parent.segment_id)
        for label, mtext in scan.metadata_texts:
            add(kind=SegmentKind.METADATA, trust=Trust.UNTRUSTED, text=mtext, raw_text=mtext,
                label=f"{att.filename}#{label}", parent_id=parent.segment_id)

    for call in iv.proposed_tool_calls:
        args = json.dumps(call.arguments, ensure_ascii=False)
        add(kind=SegmentKind.TOOL_CALL, trust=Trust.SEMI_TRUSTED, text=f"{call.name} {args}",
            raw_text=args, label=call.name, source_path=call.source_path)

    return segs
