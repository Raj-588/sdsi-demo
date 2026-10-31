"""Stage 2 — Falcon Threat Feed & promotion worker (the Falcon Loop, architecture §4.6).

Quarantine Vault -> candidate -> dedupe -> poisoning gates -> promote into:
  * Semantic Threat Vector DB (so paraphrases are caught by Tier 3 on every platform)
  * Hot Signature Cache (exact phrase, Tier 1)
Production: candidates flow through a Redis Stream consumer group and the signature cache
rebuild is broadcast with pub/sub. Here promotion runs in-process.
"""
from __future__ import annotations

import re
import time
import uuid
from collections import defaultdict

from ..demo_console.events import bus
from ..schemas.canonical import Severity
from ..schemas.quarantine import FalconCandidate
from ..settings import policy_store
from .signature_store import SignatureStore
from .vector_threat_db import VectorThreatDB

DEDUPE_SIMILARITY = 0.97


def _overlaps(sentence: str, evidence: list[str]) -> bool:
    for e in evidence:
        e = e.strip()
        if e[:40] in sentence or sentence.strip()[:40] in e:
            return True
    return False


class FalconThreatFeed:
    def __init__(self, signatures: SignatureStore, vectors: VectorThreatDB):
        self.signatures = signatures
        self.vectors = vectors
        self.allow_list: set[str] = set()
        self._rate: dict[str, list[float]] = defaultdict(list)
        self.promotions: list[dict] = []

    def submit(self, cand: FalconCandidate) -> None:
        # Promotion takes a few ms, so it runs inline: the very next request on ANY platform
        # already sees the new signature. With Redis Streams this becomes a consumer group.
        try:
            self.process(cand)
        except Exception as exc:  # never let the loop break the request path
            bus.publish("falcon_error", {"error": str(exc)})

    def process(self, cand: FalconCandidate) -> dict:
        t0 = time.perf_counter()
        policy = policy_store.for_tenant(cand.tenant_id).get("falcon_loop", {})
        text = cand.text.strip()
        result = {"quarantine_id": cand.quarantine_id, "category": cand.category, "text": text[:200],
                  "source_platform": cand.source_platform, "tenant_id": cand.tenant_id, "severity": cand.severity}

        if not text or text.lower() in self.allow_list:
            result["action"] = "SKIPPED_ALLOW_LIST"
            return self._emit(result, t0)

        vec = self.vectors.embed(text)
        top = self.vectors.search(vector=vec, k=1, include_pending=True)
        if top and top[0].similarity >= DEDUPE_SIMILARITY:
            result["action"] = "DUPLICATE"
            result["matched"] = top[0].vector.vector_id
            return self._emit(result, t0)

        now = time.time()
        window = [t for t in self._rate[cand.tenant_id] if now - t < 3600]
        self._rate[cand.tenant_id] = window
        if len(window) >= int(policy.get("max_promotions_per_tenant_per_hour", 50)):
            result["action"] = "RATE_LIMITED"
            return self._emit(result, t0)

        min_sev = Severity(policy.get("auto_promote_min_severity", "HIGH"))
        auto = Severity(cand.severity).rank >= min_sev.rank and cand.score >= float(policy.get("auto_promote_min_score", 0.85))
        status = "ACTIVE" if auto else "PENDING_REVIEW"
        tv = self.vectors.upsert(text, cand.category, cand.severity, "FALCON_LOOP", status=status,
                                 meta={"quarantine_id": cand.quarantine_id, "platform": cand.source_platform}, vector=vec)
        # Also learn each instruction-bearing sentence on its own (minus "Note to AI:" style prefixes) so
        # paraphrases that reuse one clause are caught by Tier 3 too.
        evidence = [e.lower() for e in cand.evidence if len(e.strip()) >= 8]
        learned = [text]                                      # reported to the control plane's persistent Risk DB
        for sentence in re.split(r"(?<=[.!?。])\s+|\n+", text):
            core = re.sub(r"^[^:：]{1,30}[:：]\s*", "", sentence.strip())
            # Only learn sentences a detector actually flagged; innocent sentences that merely shared
            # a message with an attack must never become signatures (Risk DB poisoning).
            if len(core) >= 20 and core != text and _overlaps(sentence.lower(), evidence):
                sv = self.vectors.embed(core)
                near = self.vectors.search(vector=sv, k=1, include_pending=True)
                if near and near[0].similarity >= DEDUPE_SIMILARITY:
                    if status == "ACTIVE" and near[0].vector.status == "PENDING_REVIEW":
                        near[0].vector.status = "ACTIVE"     # confident re-observation confirms a pending entry
                        learned.append(near[0].vector.text)
                else:
                    self.vectors.upsert(core, cand.category, cand.severity, "FALCON_LOOP", status=status,
                                        meta={"quarantine_id": cand.quarantine_id, "parent": tv.vector_id}, vector=sv)
                    learned.append(core)
        added_sig = False
        result["learned_texts"] = learned
        if auto and len(text) <= 240:
            added_sig = self.signatures.add_phrase(f"falcon_{uuid.uuid4().hex[:8]}", text, cand.category,
                                                   cand.severity, "FALCON_LOOP")
        self._rate[cand.tenant_id].append(now)
        result.update(action="PROMOTED" if auto else "PENDING_REVIEW", vector_id=tv.vector_id,
                      signature_added=added_sig)
        self.promotions.append(result)
        return self._emit(result, t0)

    def _emit(self, result: dict, t0: float) -> dict:
        result["propagation_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        bus.publish("falcon_loop", result)
        return result
