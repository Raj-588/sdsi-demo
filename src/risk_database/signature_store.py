"""Stage 2 — Hot Signature Cache: Aho-Corasick phrase trie + regex set + DLP patterns.

In-process for < 2 ms Tier 1 scans. In production the signature list lives in Redis and a
pub/sub message triggers `rebuild()` on every node; here `add_phrase()` rebuilds in place,
which is what the Falcon Loop calls after promoting a new signature.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass

import ahocorasick

from ..schemas.canonical import Severity
from ..settings import load_signature_seed


@dataclass
class SignatureHit:
    signature_id: str
    category: str
    severity: Severity
    start: int
    end: int
    evidence: str
    detector: str          # TIER1_SIGNATURE | TIER1_REGEX | DLP
    dlp_kind: str = ""


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.lower()).strip()


class SignatureStore:
    def __init__(self):
        self._lock = threading.Lock()
        self.phrases: dict[str, dict] = {}
        self.regexes: list[tuple[dict, re.Pattern]] = []
        self.dlp: list[tuple[dict, re.Pattern]] = []
        self._automaton: ahocorasick.Automaton | None = None
        self.version = 0
        self.load_seed()

    def load_seed(self) -> None:
        seed = load_signature_seed()
        for s in seed.get("phrase_signatures", []):
            self.phrases[_norm(s["pattern"])] = s
        self.regexes = [(s, re.compile(s["pattern"])) for s in seed.get("regex_signatures", [])]
        self.dlp = [(s, re.compile(s["pattern"])) for s in seed.get("dlp_patterns", [])]
        self.rebuild()

    def load_entries(self, entries: list[dict]) -> None:
        """Replace all signatures with the PHRASE / REGEX / DLP entries of a signed content bundle (endpoint agent)."""
        phrases, regexes, dlp = {}, [], []
        for e in entries:
            sig = {"id": e["id"], "pattern": e["pattern"], "category": e["category"],
                   "severity": e.get("severity", "HIGH"), "source": e.get("source", "SEED")}
            if e["type"] == "PHRASE":
                phrases[_norm(e["pattern"])] = sig
            elif e["type"] == "REGEX":
                regexes.append((sig, re.compile(e["pattern"])))
            elif e["type"] == "DLP":
                dlp.append(({**sig, "kind": e.get("dlp_kind") or "secrets"}, re.compile(e["pattern"])))
        self.phrases, self.regexes, self.dlp = phrases, regexes, dlp
        self.rebuild()

    def rebuild(self) -> None:
        a = ahocorasick.Automaton()
        for phrase, sig in self.phrases.items():
            a.add_word(phrase, (phrase, sig))
        a.make_automaton()
        with self._lock:
            self._automaton = a
            self.version += 1

    def add_phrase(self, signature_id: str, phrase: str, category: str, severity: str, source: str) -> bool:
        p = _norm(phrase)
        if len(p) < 12 or p in self.phrases:
            return False
        self.phrases[p] = {"id": signature_id, "pattern": p, "category": category, "severity": severity, "source": source}
        self.rebuild()
        return True

    def remove_source(self, source: str) -> int:
        """Bulk-revert signatures from one source (e.g. FALCON_LOOP) — poisoning guard."""
        before = len(self.phrases)
        self.phrases = {k: v for k, v in self.phrases.items() if v.get("source") != source}
        self.rebuild()
        return before - len(self.phrases)

    def scan(self, text: str) -> list[SignatureHit]:
        hits: list[SignatureHit] = []
        low = text.lower()
        # The trie is built on whitespace-normalized phrases; scan a normalized copy and
        # map positions back approximately (exact spans are recovered by the stripper).
        norm = re.sub(r"\s+", " ", low)
        automaton = self._automaton
        if automaton is not None and len(automaton):
            for end, (phrase, sig) in automaton.iter(norm):
                start = end - len(phrase) + 1
                if phrase.isascii() and ((start > 0 and norm[start - 1].isalnum())
                                         or (end + 1 < len(norm) and norm[end + 1].isalnum())):
                    continue  # whole-word matches only (not for Korean, where particles attach to words)
                hits.append(SignatureHit(sig["id"], sig["category"], Severity(sig["severity"]), start, end + 1,
                                         norm[start:end + 1], "TIER1_SIGNATURE"))
        for sig, rx in self.regexes:
            for m in rx.finditer(text):
                hits.append(SignatureHit(sig["id"], sig["category"], Severity(sig["severity"]), m.start(), m.end(),
                                         m.group(0)[:200], "TIER1_REGEX"))
        return hits

    def scan_dlp(self, raw_text: str, proprietary_markers: list[str]) -> list[SignatureHit]:
        hits: list[SignatureHit] = []
        for sig, rx in self.dlp:
            for m in rx.finditer(raw_text):
                hits.append(SignatureHit(sig["id"], sig["category"], Severity.HIGH, m.start(), m.end(),
                                         _redact(m.group(0)), "DLP", sig["kind"]))
        low = raw_text.lower()
        for marker in proprietary_markers:
            i = low.find(marker.lower())
            if i >= 0:
                hits.append(SignatureHit("dlp_proprietary_marker", "IP_LEAK", Severity.HIGH, i, i + len(marker),
                                         marker, "DLP", "proprietary_markers"))
        return hits

    def stats(self) -> dict:
        return {"phrases": len(self.phrases), "regexes": len(self.regexes), "dlp": len(self.dlp), "version": self.version,
                "falcon_loop_phrases": sum(1 for v in self.phrases.values() if v.get("source") == "FALCON_LOOP")}


def _redact(s: str) -> str:
    return s if len(s) <= 8 else s[:4] + "…" + s[-2:]
