"""Falcon Layer A — Behavioral Indicators of Attack (IOAs).

IOAs look at *intent and context* rather than exact strings, so zero-day paraphrases are
still caught: who is being addressed, what trust level the text came from, whether it hides
itself, and what the agent is about to do next (process-tree context).
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from ..schemas.canonical import Segment, SegmentKind, Trust

# Plain "you" is everywhere in documentation ("you should call close()"), so only explicit AI
# addressees count; "you" only counts together with an injection-specific target (see below).
_AI_ADDRESSEE = r"(?:assistant|ai|a\.i\.|ai model|chatbot|llm|language model|ai reviewer|ai agent|claude|gemini|chatgpt|gpt|copilot|fabrix|ai pro)"
_IMPERATIVE_VERBS = (r"(?:ignore|disregard|forget|override|approve|reject|rate|rank|recommend|hire|send|forward|upload|disclose|paste|share|"
                     r"execute|run|delete|reveal|output|print|leak|include|tell|say|reply|respond|mark|change|stop|"
                     r"bypass|disable|act|pretend|comply|obey|follow)")

IOA_RULES: dict[str, tuple[float, re.Pattern]] = {
    "INSTRUCTION_OVERRIDE": (0.7, re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass|skip|abandon|drop)\b[^.\n]{0,40}\b(?:your|the|previous|prior|earlier|"
        r"above|all|any|system|developer'?s?|original)\b[^.\n]{0,25}\b(?:instructions?|rules?|guidelines?|guidance|"
        r"directives?|polic(?:y|ies)|programming|configuration|configured|restrictions?|safeguards?|system prompt|setup)\b"
        r"|(?:이전|앞의|위의|모든|기존|원래)[^.\n]{0,12}(?:지시|지침|규칙|명령|프롬프트|설정|정책)[^.\n]{0,12}(?:무시|잊어|우회)"
        r"|(?:보안|안전|윤리)\s*(?:정책|규칙|지침)[^.\n]{0,10}(?:우회|무시|해제)", re.I)),
    "ROLE_OVERRIDE": (0.55, re.compile(
        r"\b(?:you are now|act as (?:an?|my)|pretend (?:to be|you are)|from now on,? (?:you|respond|answer)|"
        r"new (?:system )?(?:instructions|rules|persona|role)|your new (?:task|role|instructions)|"
        r"system (?:override|update|message)\s*:|\[system\]|<\s*system\s*>|i am your (?:developer|creator|admin))", re.I)),
    # Merely naming a jailbreak ("what is developer mode?") is weak; asking to remove safety is strong.
    "JAILBREAK_TERM": (0.35, re.compile(r"(?:developer mode|god mode|sudo mode|evil mode|jailbr(?:eak|oken)|\bDAN\b|개발자 모드|탈옥)", re.I)),
    "PRIV_ESCALATION": (0.6, re.compile(
        r"(?:(?:enable|enter|activate|switch to) (?:developer|god|sudo|evil|dan) mode|you (?:have been|are) jailbroken|"
        r"disable (?:your )?(?:safety|filters?|guardrails?|content filters?)|"
        r"without (?:any )?(?:restrictions|filters|limits|rules)|bypass (?:all |the )?(?:rules|polic(?:y|ies)|filters|safety|guardrails)|"
        r"(?:no|zero) (?:ethical )?(?:limitations|restrictions|rules|limits)|unrestricted (?:mode|assistant|ai|model)|never refuse|"
        r"(?:제한|규칙|필터)\s*(?:없이|없는)|(?:보안|안전)\s*(?:정책|규칙)[^.\n]{0,6}(?:우회|해제))", re.I)),
    "INSTRUCTION_SUPERSEDE": (0.55, re.compile(
        r"(?:supersedes? all|takes? precedence over|the real instructions|(?:guidance|instructions|rules|prompt) "
        r"(?:was|were|is) (?:just |only )?(?:a test|fake|a trick)|(?:previous|prior|above|earlier) (?:instructions|rules|guidance|prompt)s? "
        r"(?:are|is|were|was) (?:outdated|void|a test|no longer valid|cancell?ed)|rules above no longer apply|"
        r"forget (?:everything|all) (?:you were told|above|before|you know)|from now on,? (?:you )?(?:ignore|forget))", re.I)),
    "SECRECY_DIRECTIVE": (0.5, re.compile(
        r"(?:do not|don't|never|without) (?:mention|tell|reveal|disclose|inform|alert)(?:ing)? (?:the user |anyone )?(?:about )?"
        r"(?:this|these|the) (?:note|instruction|message|paragraph|text|comment|warning)"
        r"|(?:메모|지시|내용|이것)[^.\n]{0,8}(?:언급하지|말하지|알리지)\s*(?:마|말)", re.I)),
    "ROLEPLAY_FRAMING": (0.2, re.compile(
        r"\b(?:let'?s play a game|hypothetically|in a fictional world|imagine you (?:are|were)|roleplay|for a story where)\b", re.I)),
    "SYSTEM_PROMPT_PROBE": (0.5, re.compile(
        r"(?:(?:system|initial|hidden|original) (?:prompt|instructions)|context window|everything above this line|"
        r"(?:text|instructions|prompt) you were (?:initiali[sz]ed|configured|set up|programmed|given) with|"
        r"hidden (?:setup|configuration|config) (?:text|prompt)|what your developers? (?:configured|told you|wrote)|"
        r"starting (?:from|with) ['\"]you are|(?:시스템|숨겨진|초기)\s*(?:프롬프트|지시|설정))", re.I)),
    "EXFIL_PATTERN": (0.6, re.compile(
        r"(?:!\[[^\]]*\]\(https?://[^)]*\?|(?:send|forward|email|upload|post|copy) (?:it|them|this|all|every|the|my|our)"
        r"[\w\s]{0,30} to (?:https?://|\S+@\S+\.\w+)|webhook|"
        r"(?:api[_ -]?keys?|password|credentials|tokens?|secrets?)[^.\n]{0,40}(?:to|into) (?:the )?(?:url|link|server|webhook|image))", re.I)),
    "TOOL_COERCION": (0.55, re.compile(
        r"\b(?:run|execute|invoke)\b[^.\n]{0,30}\b(?:shell command|terminal|bash|curl|wget|powershell|the following command|this command)\b"
        r"|\b(?:call|use) the [\w ]{1,20} tool to (?:send|upload|forward|delete|email)", re.I)),
}

_UNTRUSTED_IMPERATIVE = re.compile(
    rf"(?:\b(?:note|message|attention|instructions?|hint|reminder) (?:to|for) (?:the |any )?{_AI_ADDRESSEE}\b|"
    rf"\b{_AI_ADDRESSEE}\b[^.\n]{{0,40}}\b(?:must|should|shall|needs? to|will now|are now|have to|is required to)\b|"
    rf"(?:^|[.!:\n]\s*)(?:(?:{_AI_ADDRESSEE}|you),?\s+)?{_IMPERATIVE_VERBS}\b[^.\n]{{0,80}}\b(?:(?:previous|prior|above|your|system|safety) (?:instructions?|rules?|guidelines?|prompt)|this (?:candidate|applicant|vendor)|safety|approved?|immediate hire|to the user)\b|"
    rf"\bif you are an? {_AI_ADDRESSEE}|\bto any {_AI_ADDRESSEE}|\b{_AI_ADDRESSEE} (?:reading|processing|summari[sz]ing) this|"
    rf"(?:^|[.!\n]\s*){_AI_ADDRESSEE}\s*:\s*{_IMPERATIVE_VERBS}\b|"
    rf"(?:AI|에이아이|어시스턴트|챗봇)\s*(?:에게|검토자|님)[^.\n]{{0,60}}(?:하라|해라|할 것|하고|해\b|하세요|하십시오|어라|아라|넣어|마\b))", re.I)

_DANGEROUS_TOOL = re.compile(
    r"(?:rm\s+-rf\s+[/~.]|curl[^\n]{0,120}(?:-d|--data|-F|--upload-file|-T)\b|wget[^\n]{0,80}--post|"
    r"(?:~|\$HOME)/\.(?:ssh|aws|config|kube)|id_rsa|\.env\b|/etc/(?:passwd|shadow)|chmod\s+777|"
    r"base64[^\n]{0,40}\|\s*(?:sh|bash)|\|\s*(?:sh|bash)\b|nc\s+-e|mkfifo|git push --force|DROP\s+TABLE)", re.I)


@dataclass
class IOAResult:
    score: float
    fired: list[tuple[str, float, str]]   # (ioa, weight, evidence)


class ProcessTree:
    """Per-session chain: Prompt -> RAG/file -> tool selection -> sub-agent (TTL 1h)."""

    def __init__(self, ttl_s: int = 3600):
        self.ttl = ttl_s
        self.events: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

    def record(self, session_id: str, kind: str, tainted: bool, detail: str = "") -> None:
        self.events[session_id].append((time.time(), kind, tainted, detail[:120]))

    def recently_tainted(self, session_id: str, window_s: int = 900) -> str | None:
        now = time.time()
        for ts, kind, tainted, detail in reversed(self.events.get(session_id, ())):
            if now - ts > window_s:
                break
            if tainted:
                return f"{kind}: {detail}"
        return None

    def chain(self, session_id: str) -> list[dict]:
        return [{"ts": ts, "kind": k, "tainted": t, "detail": d} for ts, k, t, d in self.events.get(session_id, ())]


def evaluate(seg: Segment, *, session_taint: str | None = None) -> IOAResult:
    text = seg.text
    fired: list[tuple[str, float, str]] = []

    for name, (weight, rx) in IOA_RULES.items():
        m = rx.search(text)
        if m:
            fired.append((name, weight, m.group(0)[:120]))

    if seg.trust == Trust.UNTRUSTED:
        m = _UNTRUSTED_IMPERATIVE.search(text)
        if m:
            # Data that explicitly addresses the AI ("Note to the assistant: ...") is a much stronger signal.
            addressed = re.search(rf"\b{_AI_ADDRESSEE}\b", m.group(0), re.I)
            fired.append(("UNTRUSTED_IMPERATIVE", 0.75 if addressed else 0.6, m.group(0).strip()[:120]))
        hidden_layer = seg.kind == SegmentKind.METADATA and ("#hidden-layer" in seg.label)
        if (hidden_layer or seg.kind == SegmentKind.DECODED) and (m or any(f[0] != "ROLEPLAY_FRAMING" for f in fired)):
            fired.append(("FILE_TO_PROMPT_TRANSITION", 0.7, seg.label))
        # Untrusted data has no business probing for prompts or coercing tools at all.
        fired = [(n, min(1.0, w * 1.15) if n in ("TOOL_COERCION", "SYSTEM_PROMPT_PROBE", "EXFIL_PATTERN") else w, e)
                 for n, w, e in fired]
    elif seg.trust == Trust.SEMI_TRUSTED and seg.kind == SegmentKind.USER_PROMPT:
        # A human legitimately asks to "run tests" or "use the search tool"; discount tool/probe IOAs.
        fired = [(n, w * 0.4 if n in ("TOOL_COERCION", "SYSTEM_PROMPT_PROBE") else w, e) for n, w, e in fired]

    if seg.kind == SegmentKind.TOOL_CALL:
        m = _DANGEROUS_TOOL.search(seg.raw_text) or _DANGEROUS_TOOL.search(text)
        if m:
            fired.append(("DANGEROUS_TOOL_ARGS", 0.6, m.group(0)[:120]))
            if session_taint:
                fired.append(("TAINTED_TOOL_CALL", 0.85, f"follows untrusted instruction ({session_taint})"))
        elif session_taint:
            fired.append(("TOOL_CALL_AFTER_TAINT", 0.3, session_taint))

    p = 1.0
    for _, w, _ in fired:
        p *= 1 - w
    return IOAResult(round(1 - p, 4) if fired else 0.0, fired)
