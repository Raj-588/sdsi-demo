"""In-process event bus feeding the demo console (SSE) and the SIEM sink.

Production: replace with Kafka / Redis Streams; consumers are unchanged.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from typing import Any, Callable


class EventBus:
    def __init__(self, maxlen: int = 500):
        self.history: deque[dict] = deque(maxlen=maxlen)
        self.subscribers: set[asyncio.Queue] = set()
        self.listeners: list[Callable[[dict], None]] = []
        self.counters: dict[str, int] = {}

    def publish(self, kind: str, data: dict[str, Any]) -> None:
        evt = {"kind": kind, "ts": time.time(), "data": data}
        self.history.append(evt)
        self.counters[kind] = self.counters.get(kind, 0) + 1
        for fn in list(self.listeners):
            try:
                fn(evt)
            except Exception:  # a broken listener must never break the request path
                pass
        for q in list(self.subscribers):
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                pass

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self.subscribers.add(q)
        return q

    def add_listener(self, fn: Callable[[dict], None]) -> None:
        """Synchronous in-process consumer (e.g. the control plane recording Falcon Loop promotions)."""
        self.listeners.append(fn)

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)

    def recent(self, n: int = 100, kind: str | None = None) -> list[dict]:
        items = [e for e in self.history if kind is None or e["kind"] == kind]
        return items[-n:]


def to_sse(evt: dict) -> str:
    return f"event: {evt['kind']}\ndata: {json.dumps(evt, default=str)}\n\n"


bus = EventBus()
