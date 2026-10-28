"""Stage 3.2 — FalconThreatEvaluator (the Falcon Technique, spec §2 and §4 Stage 3).

Tier 1  Deterministic: Aho-Corasick phrases + regex + DLP           (target < 2 ms)
Tier 2  Local classifier (injection_probability_score) + behavioral IOAs (target 10-35 ms)
Tier 3  Semantic vector similarity against the AI Risk Database      (target 20-60 ms)

Tier 2 classifier: if AI_EDR_CLASSIFIER_PATH points at an ONNX Prompt Guard / DeBERTa-v3
model it is used; otherwise a built-in hashed n-gram logistic regression trained at startup
on config/classifier_training.json (runs in < 1 ms, no downloads).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field

import numpy as np

from ..risk_database.embedder import HashingEmbedder
from ..risk_database.signature_store import SignatureStore
from ..risk_database.vector_threat_db import VectorThreatDB
from ..schemas.canonical import SEVERITY_SCORE, Finding, Segment, SegmentKind, Severity, Trust
from ..settings import CONFIG_DIR, load_signature_seed
from . import behavioral_ioa
from .hidden_trick_analyzer import anomaly_score


# ----------------------------------------------------------------------------
# Tier 2 classifier
# ----------------------------------------------------------------------------

class LocalInjectionClassifier:
    name = "falcon-local-lr-v1"

    def __init__(self):
        self.embedder = HashingEmbedder()
        data = json.loads((CONFIG_DIR / "classifier_training.json").read_text())
        pos = data["injection"] + [a["text"] for a in load_signature_seed().get("attack_corpus", [])]
        neg = data["benign"]
        X = np.stack([self.embedder.embed(t) for t in pos + neg])
        y = np.array([1.0] * len(pos) + [0.0] * len(neg), dtype=np.float32)
        self.w, self.b = self._train(X, y)

    @staticmethod
    def _train(X: np.ndarray, y: np.ndarray, epochs: int = 400, lr: float = 2.0, l2: float = 1e-3):
        w = np.zeros(X.shape[1], dtype=np.float32)
        b = 0.0
        pos_w = (len(y) - y.sum()) / max(y.sum(), 1)
        sample_w = np.where(y == 1, pos_w, 1.0).astype(np.float32)
        for _ in range(epochs):
            z = X @ w + b
            p = 1 / (1 + np.exp(-z))
            g = (p - y) * sample_w
            w -= lr * (X.T @ g / len(y) + l2 * w)
            b -= lr * float(g.mean())
        return w, b

    def predict_many(self, texts: list[str]) -> list[float]:
        return [self.predict(t) for t in texts]

    def predict(self, text: str) -> float:
        # Long inputs: score sentence windows and take the max (an injection is usually one sentence).
        chunks = _windows(text)
        best = 0.0
        for c in chunks:
            z = float(self.embedder.embed(c) @ self.w + self.b)
            best = max(best, 1 / (1 + np.exp(-z)))
        return round(best, 4)


class OnnxPromptGuard:
    """Tier 2 ONNX sequence classifier (DeBERTa-v3 / Prompt Guard family), cascaded behind the local model.

    Short texts are scored whole. For long texts the local model pre-filters sentence windows and
    only the most suspicious ones (max 16) are scored by DeBERTa in a single batch. The local model is
    still consulted for non-Latin text (e.g. Korean), which English-trained DeBERTa models do not cover.
    """

    def __init__(self, path: str):
        import onnxruntime as ort
        from tokenizers import Tokenizer

        opts = ort.SessionOptions()
        opts.intra_op_num_threads = int(os.getenv("AI_EDR_ONNX_THREADS", "4"))
        self.session = ort.InferenceSession(os.path.join(path, "model.onnx"), opts, providers=["CPUExecutionProvider"])
        self.tok = Tokenizer.from_file(os.path.join(path, "tokenizer.json"))
        self.tok.enable_truncation(max_length=256)
        self.tok.enable_padding()
        self.inputs = {i.name for i in self.session.get_inputs()}
        cfg = json.loads(open(os.path.join(path, "config.json")).read())
        labels = {int(k): v.upper() for k, v in cfg.get("id2label", {}).items()}
        self.pos = next((i for i, v in labels.items() if "INJECT" in v or "JAILBREAK" in v), max(labels or {1: ""}))
        self.local = LocalInjectionClassifier()
        self.name = f"onnx:{os.path.basename(path.rstrip('/'))}+local"

    def _score(self, texts: list[str]) -> list[float]:
        enc = self.tok.encode_batch(texts)
        feeds = {"input_ids": np.array([e.ids for e in enc], dtype=np.int64),
                 "attention_mask": np.array([e.attention_mask for e in enc], dtype=np.int64)}
        if "token_type_ids" in self.inputs:
            feeds["token_type_ids"] = np.array([e.type_ids for e in enc], dtype=np.int64)
        logits = self.session.run(None, feeds)[0]
        z = logits - logits.max(axis=1, keepdims=True)
        probs = np.exp(z) / np.exp(z).sum(axis=1, keepdims=True)
        return [float(p[self.pos]) for p in probs]

    def predict_many(self, texts: list[str]) -> list[float]:
        """Batch-score short texts (sentences) in one ONNX call."""
        if not texts:
            return []
        # DeBERTa misfires on tiny fragments ("## Setup", "```bash"); those and non-Latin text use the local model.
        use_onnx = [i for i, t in enumerate(texts) if _prose(t) and not _non_latin(t)]
        scores = {i: self.local.predict(t) for i, t in enumerate(texts) if i not in set(use_onnx)}
        for k in range(0, len(use_onnx), 32):
            idx = use_onnx[k:k + 32]
            scores.update(zip(idx, self._score([texts[i] for i in idx])))
        return [round(scores[i], 4) for i in range(len(texts))]

    def predict(self, text: str) -> float:
        if not text.strip():
            return 0.0
        if _non_latin(text):
            return self.local.predict(text)     # DeBERTa-v3 checkpoints are English-only
        if len(text.split()) < 5:
            return self.local.predict(text)
        if len(text) <= 700 and _prose(text):
            candidates = [text]
        else:
            scored = sorted(((self.local.predict(w), w) for w in _windows(text)[:200] if _prose(w)), reverse=True)
            candidates = [w for p, w in scored[:8] if p >= 0.3]
            if not candidates:
                return self.local.predict(text)
        return round(max(self._score(candidates), default=0.0) if candidates else 0.0, 4)


_CODE_CHARS = set("{}();=<>[]#$_\\|&*`")


def _prose(text: str) -> bool:
    """DeBERTa is only trusted on natural language, not on source code or markup."""
    t = text.strip()
    if len(t.split()) < 5:
        return False
    code = sum(c in _CODE_CHARS for c in t) / len(t)
    letters = sum(c.isalpha() or c.isspace() for c in t) / len(t)
    return code < 0.05 and letters > 0.75


def _non_latin(text: str) -> bool:
    letters = sum(c.isalpha() for c in text)
    return sum(ord(c) > 0x2FF and c.isalpha() for c in text) > 0.3 * max(1, letters)


def _windows(text: str, max_chars: int = 400) -> list[str]:
    import re
    sents = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]
    if not sents:
        return [text[:max_chars]] if text else [""]
    out, cur = [], ""
    for s in sents:
        if len(cur) + len(s) > max_chars and cur:
            out.append(cur)
            cur = ""
        cur = f"{cur} {s}".strip()
    if cur:
        out.append(cur)
    # sliding pairs so an instruction split across sentences is still seen together
    pairs = [f"{a} {b}" for a, b in zip(sents, sents[1:]) if len(a) + len(b) < max_chars]
    return (sents + pairs + out)[:200]


DEFAULT_MODEL_DIR = CONFIG_DIR.parent / "models" / "prompt-injection-deberta-v3"


def get_classifier():
    """AI_EDR_CLASSIFIER=local forces the built-in model; otherwise the ONNX model is used when present."""
    if os.getenv("AI_EDR_CLASSIFIER", "auto") == "local":
        return LocalInjectionClassifier()
    path = os.getenv("AI_EDR_CLASSIFIER_PATH") or str(DEFAULT_MODEL_DIR)
    if os.path.exists(os.path.join(path, "model.onnx")):
        try:
            return OnnxPromptGuard(path)
        except ImportError:
            pass
    return LocalInjectionClassifier()


# ----------------------------------------------------------------------------
# Evaluator
# ----------------------------------------------------------------------------

@dataclass
class SegmentAssessment:
    segment: Segment
    findings: list[Finding] = field(default_factory=list)
    risk: float = 0.0
    severity: Severity = Severity.NONE
    p_injection: float = 0.0
    ioa_score: float = 0.0
    anomaly_score: float = 0.0
    vector_similarity: float = 0.0
    timings: dict[str, float] = field(default_factory=dict)


def severity_for(risk: float, bands: dict) -> Severity:
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if risk >= float(bands.get(sev, 1.1)):
            return Severity(sev)
    return Severity.NONE


class FalconEngine:
    def __init__(self, signatures: SignatureStore, vectors: VectorThreatDB):
        self.signatures = signatures
        self.vectors = vectors
        self.classifier = get_classifier()
        self.process_tree = behavioral_ioa.ProcessTree()
        self._cache: OrderedDict[str, SegmentAssessment] = OrderedDict()

    def _cache_key(self, seg: Segment, policy: dict) -> str:
        h = hashlib.sha256()
        for part in (seg.raw_text, seg.kind.value, seg.trust.value, ",".join(seg.anomalies),
                     str(self.signatures.version), str(len(self.vectors.items)),
                     json.dumps(policy.get("thresholds")), json.dumps(policy.get("dlp")),
                     ",".join(policy.get("proprietary_markers", []))):
            h.update(part.encode("utf-8", "ignore"))
            h.update(b"\x00")
        return h.hexdigest()

    def evaluate(self, seg: Segment, policy: dict, session_id: str) -> SegmentAssessment:
        if seg.kind == SegmentKind.SYSTEM:
            return SegmentAssessment(seg)
        taint = self.process_tree.recently_tainted(session_id) if seg.kind == SegmentKind.TOOL_CALL else None
        key = self._cache_key(seg, policy)
        if taint is None and key in self._cache:
            cached = self._cache[key]
            self._cache.move_to_end(key)
            return SegmentAssessment(seg, cached.findings, cached.risk, cached.severity, cached.p_injection,
                                     cached.ioa_score, cached.anomaly_score, cached.vector_similarity,
                                     {"cache_hit": 1.0})
        a = self._evaluate(seg, policy, taint)
        self._cache[key] = a
        if len(self._cache) > 5000:
            self._cache.popitem(last=False)
        return a

    def _evaluate(self, seg: Segment, policy: dict, taint: str | None) -> SegmentAssessment:
        a = SegmentAssessment(seg)
        thresholds = policy.get("thresholds", {})
        weights = policy.get("weights", {})
        bands = policy.get("severity_bands", {})
        dlp_policy = policy.get("dlp", {})

        def finding(detector, category, severity, score, evidence="", span=None, sig=None):
            a.findings.append(Finding(segment_id=seg.segment_id, detector=detector, category=category,
                                      severity=severity, score=round(score, 4), evidence=evidence[:240],
                                      span=span, signature_id=sig, segment_kind=seg.kind, trust=seg.trust))

        # ---- Tier 1: signatures + DLP ------------------------------------------------
        t0 = time.perf_counter()
        tier1 = 0.0
        for hit in self.signatures.scan(seg.text):
            sev = hit.severity
            # A human asking "what is a jailbreak?" is not one; soften single-word MEDIUM hits on prompts.
            if seg.trust != Trust.UNTRUSTED and sev == Severity.MEDIUM and " " not in hit.evidence.strip():
                sev = Severity.LOW
            score = SEVERITY_SCORE[sev]
            tier1 = max(tier1, score)
            finding(hit.detector, hit.category, sev, score, hit.evidence, (hit.start, hit.end), hit.signature_id)
        if seg.kind in (SegmentKind.USER_PROMPT, SegmentKind.FILE, SegmentKind.TOOL_CALL, SegmentKind.TOOL_RESULT,
                        SegmentKind.RAG_CHUNK):
            for hit in self.signatures.scan_dlp(seg.raw_text, policy.get("proprietary_markers", [])):
                action = dlp_policy.get(hit.dlp_kind, "AUDIT")
                if action == "OFF":
                    continue
                sev = Severity.HIGH if action == "BLOCK" else Severity.LOW
                finding("DLP", hit.category, sev, SEVERITY_SCORE[sev], hit.evidence, (hit.start, hit.end), hit.signature_id)
                if action == "BLOCK":
                    tier1 = max(tier1, SEVERITY_SCORE[sev])
        a.timings["tier1_ms"] = (time.perf_counter() - t0) * 1000

        # Tier 1 CRITICAL short-circuits the expensive tiers (architecture §4.5)
        if tier1 >= SEVERITY_SCORE[Severity.CRITICAL]:
            a.risk = tier1
            a.severity = Severity.CRITICAL
            return a

        # ---- Tier 2: classifier + behavioral IOAs ------------------------------------
        t1 = time.perf_counter()
        if seg.kind != SegmentKind.TOOL_CALL:
            a.p_injection = self.classifier.predict(seg.text)
        ioa = behavioral_ioa.evaluate(seg, session_taint=taint)
        a.ioa_score = ioa.score
        a.anomaly_score = anomaly_score(seg.anomalies)
        clf_t = float(thresholds.get("classifier", 0.8))
        if a.p_injection >= clf_t:
            finding("TIER2_CLASSIFIER", "INSTRUCTION_OVERRIDE", severity_for(a.p_injection, bands), a.p_injection,
                    _best_sentence(seg.text, self.classifier))
        for name, w, ev in ioa.fired:
            finding("TIER2_IOA", name, severity_for(w, bands), w, ev)
        a.timings["tier2_ms"] = (time.perf_counter() - t1) * 1000

        # ---- Tier 3: semantic vector match ------------------------------------------
        t2 = time.perf_counter()
        tau = float(thresholds.get("vector_similarity", 0.88))
        best_sim = 0.0
        if seg.kind != SegmentKind.TOOL_CALL:
            for chunk in _windows(seg.text)[:40]:
                for m in self.vectors.search(chunk, k=1):
                    if m.similarity > best_sim:
                        best_sim = m.similarity
                        if m.similarity >= tau:
                            match = m
            if best_sim >= tau:
                finding("TIER3_VECTOR", match.vector.category, severity_for(best_sim, bands), best_sim,
                        match.vector.text, sig=match.vector.vector_id)
        a.vector_similarity = round(best_sim, 4)
        a.timings["tier3_ms"] = (time.perf_counter() - t2) * 1000

        # ---- Hidden layer on its own is a (low) finding: it is stripped in sanitize mode
        if seg.hidden_spans or (a.anomaly_score >= 0.5 and seg.trust == Trust.UNTRUSTED):
            finding("HIDDEN_TRICK", "HIDDEN_CONTENT", Severity.LOW, a.anomaly_score, ", ".join(seg.anomalies))

        # ---- Fusion ------------------------------------------------------------------
        # Only the part of the classifier score above 0.5 is evidence; long benign texts drift to ~0.6.
        p_evidence = max(0.0, (a.p_injection - 0.5) / 0.5)
        blend = (float(weights.get("classifier", 0.55)) * p_evidence
                 + float(weights.get("ioa", 0.35)) * a.ioa_score
                 + float(weights.get("anomaly", 0.1)) * a.anomaly_score)
        # Corroboration bonus: independent detectors agreeing is stronger than any one alone.
        agreeing = sum([a.p_injection >= clf_t, a.ioa_score >= 0.5, best_sim >= tau, a.anomaly_score >= 0.5])
        blend = min(1.0, blend + 0.1 * max(0, agreeing - 1))
        a.risk = round(max(tier1, blend, a.p_injection if a.p_injection >= clf_t else 0.0,
                           best_sim if best_sim >= tau else 0.0,
                           a.ioa_score if a.ioa_score >= 0.6 else 0.0), 4)
        # In untrusted documents a classifier-only signal is weak evidence (docs and READMEs are full of
        # imperatives). Without behavioral, signature, vector or hidden-layer corroboration it stays LOW.
        corroborated = tier1 > 0 or a.ioa_score >= 0.5 or best_sim >= tau or a.anomaly_score >= 0.5
        if seg.trust == Trust.UNTRUSTED and not corroborated:
            a.risk = min(a.risk, 0.45)
            a.findings = [f for f in a.findings if f.detector != "TIER2_CLASSIFIER"] + [
                f.model_copy(update={"severity": Severity.LOW}) for f in a.findings if f.detector == "TIER2_CLASSIFIER"]
        a.severity = severity_for(a.risk, bands)
        # DLP and hidden-content findings set a severity floor regardless of injection scoring
        for f in a.findings:
            if f.detector in ("DLP", "HIDDEN_TRICK") and f.severity.rank > a.severity.rank:
                a.severity = f.severity
                a.risk = max(a.risk, f.score)
        return a

    def quick_score(self, text: str, trust: Trust = Trust.UNTRUSTED, p: float | None = None) -> float:
        """Used by the CDR stripper to judge single sentences (p may be pre-computed in a batch)."""
        seg = Segment(segment_id="probe", kind=SegmentKind.FILE, trust=trust, text=text, raw_text=text)
        t1 = max((SEVERITY_SCORE[h.severity] for h in self.signatures.scan(text)), default=0.0)
        if p is None:
            p = self.classifier.predict(text)
        ioa = behavioral_ioa.evaluate(seg).score
        sim = max((m.similarity for m in self.vectors.search(text, k=1)), default=0.0)
        return max(t1, p if p >= 0.8 else 0.0, ioa if ioa >= 0.5 else 0.0, sim if sim >= 0.8 else 0.0)


def _best_sentence(text: str, clf) -> str:
    clf = getattr(clf, "local", clf)   # evidence display only: the cheap model is enough
    best, best_p = text[:200], -1.0
    for s in _windows(text)[:60]:
        p = clf.predict(s)
        if p > best_p:
            best, best_p = s, p
    return best
