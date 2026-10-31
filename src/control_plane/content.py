"""Content pipeline: snapshot the Risk DB -> quality gate -> Ed25519-signed bundle -> ring rollout.

This is the lesson of the July 2024 CrowdStrike outage applied to AI-EDR: Risk DB updates are *content*
that reaches every endpoint, so no bundle ships unless it (1) still catches the attack corpus, (2) raises
zero alerts on a benign corpus, and (3) is signed; and it reaches CANARY machines before everyone else.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..settings import CONFIG_DIR, load_signature_seed

BUNDLE_FORMAT = "aiedr-content/1"
AGENT_FIELDS = ("id", "type", "pattern", "category", "severity", "dlp_kind", "source", "owasp", "atlas", "tier")
GATE_MIN_RECALL = float(os.getenv("AI_EDR_GATE_MIN_RECALL", "0.85"))
GATE_MAX_RECALL_DROP = 0.05
VECTOR_THRESHOLD = 0.80


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class ContentSigner:
    """Ed25519 signing key for content bundles. Production: the private key lives in an HSM / cloud KMS."""

    def __init__(self, key_dir: Path):
        key_dir.mkdir(parents=True, exist_ok=True)
        path = key_dir / "content_signing_ed25519.pem"
        if path.exists():
            self._key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            self._key = Ed25519PrivateKey.generate()
            path.write_bytes(self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
            path.chmod(0o600)
        raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key_b64 = base64.b64encode(raw).decode()
        self.key_id = hashlib.sha256(raw).hexdigest()[:16]

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self._key.sign(data)).decode()


def verify_bundle(bundle: dict, public_key_b64: str) -> list[dict]:
    """Agent-side check: signature over the manifest, then the manifest's hash over the entries. Raises on tamper."""
    manifest = bundle["manifest"]
    if manifest.get("format") != BUNDLE_FORMAT:
        raise ValueError(f"unsupported bundle format {manifest.get('format')}")
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    pub.verify(base64.b64decode(bundle["signature"]), canonical(manifest))      # raises InvalidSignature
    if hashlib.sha256(canonical(bundle["entries"])).hexdigest() != manifest["sha256"]:
        raise ValueError("bundle entries do not match the signed manifest hash")
    return bundle["entries"]


def agent_view(entries: list[dict], tenant_id: str) -> list[dict]:
    """GLOBAL entries plus this tenant's own TENANT entries; other tenants' learned data never leaves them."""
    out = [{k: e.get(k) for k in AGENT_FIELDS} for e in entries
           if e["tier"] == "GLOBAL" or e.get("tenant_id") == tenant_id]
    return sorted(out, key=lambda e: e["id"])


def entries_sha(entries: list[dict]) -> str:
    return hashlib.sha256(canonical(entries)).hexdigest()


def build_bundle(release: dict, tenant_id: str, signer: ContentSigner) -> dict:
    entries = agent_view(release["entries"], tenant_id)
    manifest = {"format": BUNDLE_FORMAT, "version": release["version"], "tenant_id": tenant_id,
                "created_at": release["created_at"], "ring": release["ring"], "entry_count": len(entries),
                "sha256": entries_sha(entries), "key_id": signer.key_id}
    return {"manifest": manifest, "entries": entries, "signature": signer.sign(canonical(manifest))}


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------

def gate_corpus() -> dict:
    data = json.loads((CONFIG_DIR / "gate_corpus.json").read_text())
    attacks = [a["text"] for a in load_signature_seed().get("attack_corpus", [])] + data["attacks"]
    return {"attacks": attacks, "benign": data["benign"]}


def run_gate(entries: list[dict], previous_recall: float | None = None) -> dict:
    """Replay the attack and benign corpora against a candidate snapshot, using the same Tier 1 / Tier 3
    components an endpoint will load. Returns metrics and pass/fail with reasons."""
    from ..risk_database.signature_store import SignatureStore
    from ..risk_database.vector_threat_db import VectorThreatDB

    t0 = time.perf_counter()
    sigs, vecs = SignatureStore(), VectorThreatDB()
    sigs.load_entries(entries)
    vecs.load_entries(entries)

    def hit(text: str) -> tuple[bool, str]:
        h = sigs.scan(text)
        if h:
            return True, h[0].signature_id
        m = vecs.search(text, k=1)
        if m and m[0].similarity >= VECTOR_THRESHOLD:
            return True, m[0].vector.vector_id
        return False, ""

    corpus = gate_corpus()
    missed = [t for t in corpus["attacks"] if not hit(t)[0]]
    fps = []
    for t in corpus["benign"]:
        ok, by = hit(t)
        if ok:
            fps.append({"text": t, "matched": by})
    recall = round(1 - len(missed) / max(len(corpus["attacks"]), 1), 4)
    reasons = []
    if recall < GATE_MIN_RECALL:
        reasons.append(f"recall {recall:.0%} below minimum {GATE_MIN_RECALL:.0%}")
    if previous_recall is not None and recall < previous_recall - GATE_MAX_RECALL_DROP:
        reasons.append(f"recall regressed from {previous_recall:.0%} to {recall:.0%}")
    if fps:
        reasons.append(f"{len(fps)} false positive(s) on the benign corpus")
    return {"passed": not reasons, "reasons": reasons, "recall": recall, "attacks": len(corpus["attacks"]),
            "missed": missed[:20], "benign": len(corpus["benign"]), "false_positives": len(fps), "fp_samples": fps[:20],
            "duration_ms": round((time.perf_counter() - t0) * 1000, 1)}
