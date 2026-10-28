"""Universal multi-provider adapter interface (architecture §4.1).

Every adapter turns a provider payload into a CanonicalAIEDRRequest, remembering a JSON
pointer (`source_path`) for each piece of untrusted content so a sanitized result can be
written back into the *original* provider format.
"""
from __future__ import annotations

import copy
import re
from abc import ABC, abstractmethod
from typing import Any, Mapping

from ..schemas.canonical import (
    ActorContext,
    CanonicalAIEDRRequest,
    SanitizationEdit,
    SourcePlatform,
    Verdict,
)
from ..settings import settings

_PTR_ESC = str.maketrans({"~": "~0", "/": "~1"})


def ptr(*parts: Any) -> str:
    return "/" + "/".join(str(p).translate(_PTR_ESC) for p in parts)


def _ptr_parts(pointer: str) -> list[str]:
    return [p.replace("~1", "/").replace("~0", "~") for p in pointer.lstrip("/").split("/")] if pointer else []


def get_ptr(doc: Any, pointer: str) -> Any:
    cur = doc
    for p in _ptr_parts(pointer):
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    return cur


def set_ptr(doc: Any, pointer: str, value: Any) -> None:
    parts = _ptr_parts(pointer)
    cur = doc
    for p in parts[:-1]:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


def get_path(doc: Any, path: str) -> tuple[Any, str | None]:
    """Dotted path with list indexes, e.g. 'input.query' or 'messages[-1].content'. Returns (value, json_pointer)."""
    cur, parts = doc, []
    for token in re.findall(r"[^.\[\]]+|\[-?\d+\]", path):
        if token.startswith("["):
            if not isinstance(cur, list) or not cur:
                return None, None
            i = int(token[1:-1])
            i = i if i >= 0 else len(cur) + i
            if not 0 <= i < len(cur):
                return None, None
            cur = cur[i]
            parts.append(i)
        else:
            if not isinstance(cur, dict) or token not in cur:
                return None, None
            cur = cur[token]
            parts.append(token)
    return cur, ptr(*parts)


def text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(text_of(c) for c in content)
    if isinstance(content, dict):
        for k in ("text", "content", "data"):
            if isinstance(content.get(k), str):
                return content[k]
    return ""


class BaseAdapter(ABC):
    platform: SourcePlatform

    @abstractmethod
    def to_canonical(self, raw: dict, headers: Mapping[str, str], path: str = "") -> CanonicalAIEDRRequest: ...

    @abstractmethod
    def text_block(self, text: str) -> Any:
        """Provider-native text block used to replace a binary attachment after sanitization."""

    @abstractmethod
    def block_response(self, verdict: Verdict) -> tuple[int, dict]: ...

    @abstractmethod
    def upstream_url(self, path: str, query: str = "") -> str: ...

    def actor(self, headers: Mapping[str, str], raw: dict | None = None) -> ActorContext:
        h = {k.lower(): v for k, v in headers.items()}
        ua = h.get("user-agent", "")
        actor = ActorContext(
            user_id=h.get("x-ai-edr-user", "anonymous"),
            tenant_id=h.get(settings.tenant_header.lower(), settings.default_tenant),
            client_ide_or_app=h.get("x-ai-edr-client") or (ua.split(" ")[0] if ua else "unknown"),
        )
        if h.get("x-ai-edr-session"):
            actor.session_id = h["x-ai-edr-session"]
        return actor

    def apply_sanitization(self, raw: dict, edits: list[SanitizationEdit]) -> dict:
        out = copy.deepcopy(raw)
        for e in edits:
            if not e.source_path:
                continue
            try:
                current = get_ptr(out, e.source_path)
            except (KeyError, IndexError, ValueError, TypeError):
                continue
            set_ptr(out, e.source_path, e.sanitized_text if isinstance(current, str) else self.text_block(e.sanitized_text))
        return out

    def blocked_message(self, verdict: Verdict) -> str:
        cats = sorted({f.category for f in verdict.findings if f.severity.rank >= 2}) or sorted({f.category for f in verdict.findings})
        return (f"Blocked by AI-EDR Inline Guardrail: {verdict.reason} "
                f"[severity={verdict.severity.value}, categories={','.join(cats[:4])}, quarantine_id={verdict.quarantine_id}]")


def last_index(items: list, pred) -> int:
    for i in range(len(items) - 1, -1, -1):
        if pred(items[i]):
            return i
    return -1
