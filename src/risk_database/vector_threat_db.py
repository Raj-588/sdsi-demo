"""Stage 2 — Semantic Threat Vector DB.

In-memory numpy index (default) with the same interface a Qdrant/pgvector backend would
expose: upsert() and search(). Top-k cosine similarity over ACTIVE vectors.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field

import numpy as np

from ..settings import load_signature_seed
from .embedder import get_embedder


@dataclass
class ThreatVector:
    vector_id: str
    text: str
    category: str
    severity: str
    source: str                       # SEED | FALCON_LOOP | THREAT_INTEL
    status: str = "ACTIVE"            # ACTIVE | PENDING_REVIEW | REVERTED
    meta: dict = field(default_factory=dict)


@dataclass
class VectorMatch:
    vector: ThreatVector
    similarity: float


class VectorThreatDB:
    def __init__(self):
        self.embedder = get_embedder()
        self._lock = threading.Lock()
        self.items: list[ThreatVector] = []
        self._matrix = np.zeros((0, self.embedder.dim), dtype=np.float32)
        for a in load_signature_seed().get("attack_corpus", []):
            self.upsert(a["text"], a["category"], "HIGH", "SEED")

    def embed(self, text: str) -> np.ndarray:
        return self.embedder.embed(text)

    def upsert(self, text: str, category: str, severity: str, source: str, status: str = "ACTIVE",
               meta: dict | None = None, vector: np.ndarray | None = None) -> ThreatVector:
        v = vector if vector is not None else self.embed(text)
        tv = ThreatVector(f"vec_{uuid.uuid4().hex[:10]}", text, category, severity, source, status, meta or {})
        with self._lock:
            self.items.append(tv)
            self._matrix = np.vstack([self._matrix, v[None, :]])
        return tv

    def search(self, text: str | None = None, *, vector: np.ndarray | None = None, k: int = 5,
               include_pending: bool = False) -> list[VectorMatch]:
        if not self.items:
            return []
        q = vector if vector is not None else self.embed(text or "")
        with self._lock:
            sims = self._matrix @ q
            items = list(self.items)
        order = np.argsort(-sims)
        out = []
        for i in order:
            it = items[i]
            if it.status == "ACTIVE" or (include_pending and it.status == "PENDING_REVIEW"):
                out.append(VectorMatch(it, float(sims[i])))
            if len(out) >= k:
                break
        return out

    def set_status(self, vector_id: str, status: str) -> bool:
        for it in self.items:
            if it.vector_id == vector_id:
                it.status = status
                return True
        return False

    def revert_source(self, source: str) -> int:
        n = 0
        for it in self.items:
            if it.source == source and it.status != "REVERTED":
                it.status = "REVERTED"
                n += 1
        return n

    def stats(self) -> dict:
        by = {}
        for it in self.items:
            by[f"{it.source}:{it.status}"] = by.get(f"{it.source}:{it.status}", 0) + 1
        return {"vectors": len(self.items), "embedder": self.embedder.name, "by_source_status": by}
