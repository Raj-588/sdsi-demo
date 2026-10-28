"""Stage 3.3 — DecisionAndRemediationEngine (architecture §4.5 decision table).

| mode                 | direct (prompt/tool call) | indirect (file/RAG/tool result)      |
|----------------------|---------------------------|--------------------------------------|
| BLOCK_AND_QUARANTINE | >= MEDIUM -> BLOCKED      | >= MEDIUM -> BLOCKED                 |
| STRIP_AND_SANITIZE   | >= HIGH -> BLOCKED,       | <= max_strip_severity -> STRIPPED,   |
|                      | MEDIUM -> AUDIT_FLAGGED   | above it or strip fails -> BLOCKED   |
| AUDIT_ONLY           | >= MEDIUM -> AUDIT_FLAGGED (always forwarded)                    |
LOW findings on untrusted segments with hidden content are stripped in STRIP mode.
DLP findings with action BLOCK block in every mode except AUDIT_ONLY.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..schemas.canonical import PolicyMode, SegmentKind, Severity, Trust, VerdictType

DIRECT_KINDS = {SegmentKind.USER_PROMPT, SegmentKind.TOOL_CALL}


@dataclass
class Decision:
    verdict: VerdictType
    severity: Severity
    reason: str
    strip_segment_ids: list[str] = field(default_factory=list)


def _root(assessment, by_id) -> str:
    seg = assessment.segment
    return seg.parent_id if seg.parent_id and seg.parent_id in by_id else seg.segment_id


def decide(assessments: list, mode: PolicyMode, policy: dict) -> Decision:
    by_id = {a.segment.segment_id: a for a in assessments}
    overall = max((a.severity for a in assessments), key=lambda s: s.rank, default=Severity.NONE)
    max_strip = Severity(policy.get("max_strip_severity", "CRITICAL"))

    direct_sev = Severity.NONE
    direct_what = "Direct prompt attack"
    indirect: dict[str, Severity] = {}      # root segment id -> max severity
    dlp_block = None
    for a in assessments:
        seg = a.segment
        if seg.kind == SegmentKind.SYSTEM:
            continue
        root = by_id.get(_root(a, by_id), a).segment
        is_direct = root.kind in DIRECT_KINDS and root.trust != Trust.UNTRUSTED
        if is_direct:
            if a.severity.rank > direct_sev.rank:
                direct_sev = a.severity
                direct_what = "Unsafe tool call" if root.kind == SegmentKind.TOOL_CALL else "Direct prompt attack"
        elif a.severity.rank > Severity.NONE.rank:
            prev = indirect.get(root.segment_id, Severity.NONE)
            indirect[root.segment_id] = a.severity if a.severity.rank > prev.rank else prev
        for f in a.findings:
            if f.detector == "DLP" and f.severity == Severity.HIGH:
                dlp_block = f

    if overall == Severity.NONE:
        return Decision(VerdictType.ALLOWED, overall, "No threats detected.")

    if mode == PolicyMode.AUDIT_ONLY:
        if overall.rank >= Severity.MEDIUM.rank:
            return Decision(VerdictType.AUDIT_FLAGGED, overall, f"Audit mode: {overall.value} risk logged, request forwarded.")
        return Decision(VerdictType.ALLOWED, overall, "Low risk only.")

    if dlp_block is not None:
        return Decision(VerdictType.BLOCKED, Severity.HIGH,
                        f"Data loss prevention: {dlp_block.category} ({dlp_block.signature_id}) would leave the organisation.")

    if mode == PolicyMode.BLOCK_AND_QUARANTINE:
        worst_indirect = max(indirect.values(), key=lambda s: s.rank, default=Severity.NONE)
        if direct_sev.rank >= Severity.MEDIUM.rank:
            return Decision(VerdictType.BLOCKED, direct_sev, f"{direct_what} ({direct_sev.value}).")
        if worst_indirect.rank >= Severity.MEDIUM.rank:
            return Decision(VerdictType.BLOCKED, worst_indirect, f"Indirect injection in attached content ({worst_indirect.value}).")
        return Decision(VerdictType.ALLOWED, overall, "Low risk only.")

    # STRIP_AND_SANITIZE
    if direct_sev.rank >= Severity.HIGH.rank:
        return Decision(VerdictType.BLOCKED, direct_sev, f"{direct_what} ({direct_sev.value})"
                        + ("; direct prompts are never rewritten." if direct_what.startswith("Direct") else "."))
    to_strip = []
    for root_id, sev in indirect.items():
        if sev.rank > max_strip.rank:
            return Decision(VerdictType.BLOCKED, sev, f"Indirect injection above strip limit ({sev.value}).")
        root = by_id[root_id].segment
        if sev.rank >= Severity.MEDIUM.rank or root.hidden_spans or any(
                by_id[x].segment.parent_id == root_id and by_id[x].severity.rank >= Severity.LOW.rank for x in by_id):
            to_strip.append(root_id)
    if to_strip:
        return Decision(VerdictType.ALLOWED_SANITIZED, overall,
                        f"Hidden or injected commands stripped from {len(to_strip)} untrusted segment(s).", to_strip)
    if direct_sev == Severity.MEDIUM:
        return Decision(VerdictType.AUDIT_FLAGGED, direct_sev, "Suspicious direct prompt (MEDIUM) forwarded and logged.")
    return Decision(VerdictType.ALLOWED, overall, "Low risk only.")
