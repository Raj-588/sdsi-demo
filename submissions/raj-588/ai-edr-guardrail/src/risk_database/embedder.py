"""Local text embedder for the Semantic Threat Vector DB.

Default: a dependency-free feature-hashing embedder (word uni/bi-grams + char 3-5 grams,
L2-normalized). It is deterministic, offline and < 1 ms per segment, which keeps the demo
self-contained. For production set AI_EDR_EMBEDDER=onnx and point AI_EDR_EMBEDDER_PATH at a
sentence-embedding ONNX model (e.g. all-MiniLM-L6-v2); see requirements-ml.txt.
"""
from __future__ import annotations

import hashlib
import os
import re

import numpy as np

DIM = 2048
_WORD = re.compile(r"[^\W_]+(?:'[^\W_]+)?")   # unicode-aware: Korean/Hangul tokens are kept
_STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is", "are", "be", "this", "that",
         "it", "with", "as", "at", "by", "your", "you", "me", "my", "i", "we", "our", "from", "please"}


def _h(token: str) -> tuple[int, float]:
    d = hashlib.blake2b(token.encode(), digest_size=8).digest()
    v = int.from_bytes(d, "little")
    return v % DIM, (1.0 if (v >> 63) & 1 else -1.0)


def tokenize(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in _STOP]


def featurize(text: str) -> dict[str, float]:
    words = tokenize(text)
    feats: dict[str, float] = {}
    for w in words:
        feats["w:" + w] = feats.get("w:" + w, 0) + 1.0
    for a, b in zip(words, words[1:]):
        k = f"b:{a}_{b}"
        feats[k] = feats.get(k, 0) + 1.5
    joined = " ".join(words)
    for n in (3, 4, 5):
        for i in range(len(joined) - n + 1):
            k = "c:" + joined[i:i + n]
            feats[k] = feats.get(k, 0) + 0.25
    return feats


class HashingEmbedder:
    name = "hashing-ngram-2048"
    dim = DIM

    def embed(self, text: str) -> np.ndarray:
        v = np.zeros(DIM, dtype=np.float32)
        for tok, w in featurize(text).items():
            idx, sign = _h(tok)
            v[idx] += sign * w
        n = np.linalg.norm(v)
        return v / n if n else v


class OnnxEmbedder:  # pragma: no cover - optional production path
    def __init__(self, path: str):
        import onnxruntime as ort
        from transformers import AutoTokenizer

        self.session = ort.InferenceSession(os.path.join(path, "model.onnx"))
        self.tokenizer = AutoTokenizer.from_pretrained(path)
        self.name = f"onnx:{os.path.basename(path)}"
        self.dim = self.session.get_outputs()[0].shape[-1]

    def embed(self, text: str) -> np.ndarray:
        enc = self.tokenizer(text, return_tensors="np", truncation=True, max_length=256)
        out = self.session.run(None, {k: v for k, v in enc.items()})[0]
        mask = enc["attention_mask"][..., None]
        v = (out * mask).sum(1) / mask.sum(1)
        v = v[0].astype(np.float32)
        return v / (np.linalg.norm(v) or 1.0)


def get_embedder():
    if os.getenv("AI_EDR_EMBEDDER") == "onnx" and os.getenv("AI_EDR_EMBEDDER_PATH"):
        return OnnxEmbedder(os.environ["AI_EDR_EMBEDDER_PATH"])
    return HashingEmbedder()
