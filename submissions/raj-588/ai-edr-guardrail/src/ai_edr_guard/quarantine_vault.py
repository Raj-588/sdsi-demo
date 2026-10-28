"""Stage 3.3 Path A — Trap & Quarantine Vault.

Persists a forensic record of every BLOCKED request (SQLite here; Postgres + encrypted
object storage in production), emits a SIEM/SOC alert, and feeds the Falcon Loop.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

from ..demo_console.events import bus
from ..schemas.canonical import CanonicalAIEDRRequest, Severity, Verdict
from ..schemas.quarantine import FalconCandidate, QuarantineRecord
from ..settings import settings


DLP_CATEGORIES = {"SECRET_LEAK", "IP_LEAK", "PII_LEAK"}


def _sha(data: Any) -> str:
    if not isinstance(data, (bytes, bytearray)):
        data = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(data).hexdigest()


class QuarantineVault:
    def __init__(self, data_dir: Path | None = None, feed=None):
        self.dir = data_dir or settings.data_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.dir / "quarantine.db"
        self.siem_path = self.dir / "siem_alerts.jsonl"
        self.feed = feed
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("""CREATE TABLE IF NOT EXISTS quarantine (
            quarantine_id TEXT PRIMARY KEY, created_at TEXT, tenant_id TEXT, user_id TEXT,
            source_platform TEXT, severity TEXT, status TEXT, record_json TEXT)""")
        self._conn.commit()

    def trap(self, req: CanonicalAIEDRRequest, verdict: Verdict, assessments: list,
             raw_payload: Any = None) -> QuarantineRecord:
        qid = f"qv_{uuid.uuid4().hex[:12]}"
        file_hashes = {att.filename: _sha(att.content_base64 or att.extracted_raw_text)
                       for att in req.input_vectors.indirect_attachments}
        ioa = max((a.ioa_score for a in assessments), default=0.0)
        rec = QuarantineRecord(
            quarantine_id=qid, request_id=req.request_id, tenant_id=req.actor_context.tenant_id,
            user_id=req.actor_context.user_id, session_id=req.actor_context.session_id,
            source_platform=req.source_platform.value, inspection_stage=req.inspection_stage.value,
            severity=verdict.severity.value, risk_score=verdict.risk_score,
            payload_sha256=_sha(raw_payload if raw_payload is not None else req.model_dump(mode="json")),
            file_hashes=file_hashes, findings=verdict.findings,
            matched_signatures=sorted({f.signature_id for f in verdict.findings if f.signature_id}),
            falcon_ioa_score=ioa, policy_version=verdict.policy_version,
            payload=(raw_payload if raw_payload is not None else req.model_dump(mode="json")) if settings.store_full_payloads else None,
        )
        with self._lock:
            self._conn.execute("INSERT INTO quarantine VALUES (?,?,?,?,?,?,?,?)", (
                qid, rec.created_at.isoformat(), rec.tenant_id, rec.user_id, rec.source_platform,
                rec.severity, rec.status, rec.model_dump_json()))
            self._conn.commit()
        self._siem_alert(rec, verdict)
        self._feed_falcon_loop(rec, assessments)
        return rec

    def _siem_alert(self, rec: QuarantineRecord, verdict: Verdict) -> None:
        alert = {
            "cef": f"CEF:0|AI-EDR|InlineGuardrail|1.0|{verdict.findings[0].category if verdict.findings else 'BLOCK'}|"
                   f"AI prompt attack blocked|{ {'CRITICAL': 10, 'HIGH': 8, 'MEDIUM': 5}.get(rec.severity, 3) }|",
            "quarantine_id": rec.quarantine_id, "tenant": rec.tenant_id, "user": rec.user_id,
            "platform": rec.source_platform, "severity": rec.severity, "risk": rec.risk_score,
            "categories": sorted({f.category for f in verdict.findings}), "ts": rec.created_at.isoformat(),
        }
        with open(self.siem_path, "a") as fh:
            fh.write(json.dumps(alert) + "\n")
        bus.publish("siem_alert", alert)

    def _feed_falcon_loop(self, rec: QuarantineRecord, assessments: list) -> None:
        if self.feed is None:
            return
        seen = set()
        for a in assessments:
            if a.severity.rank < Severity.HIGH.rank or a.segment.kind.value in ("SYSTEM", "TOOL_CALL"):
                continue
            # DLP hits are leaked data, not attacks: never copy secrets / proprietary code into the shared Risk DB.
            if any(f.detector == "DLP" or f.category in DLP_CATEGORIES for f in a.findings):
                continue
            # Use the offending sentence(s), not the whole document, as the new signature.
            strong = [f for f in a.findings if f.severity.rank >= Severity.HIGH.rank and f.detector != "HIDDEN_TRICK"]
            # No self-reinforcement: a block caused only by previously learned entries teaches nothing new.
            if strong and all(self._learned(f) for f in strong):
                continue
            evidence = _offending_text(a)
            if not evidence or evidence in seen:
                continue
            seen.add(evidence)
            cat = next((f.category for f in a.findings if f.detector in ("TIER1_SIGNATURE", "TIER3_VECTOR", "TIER1_REGEX")),
                       a.findings[0].category if a.findings else "INSTRUCTION_OVERRIDE")
            self.feed.submit(FalconCandidate(quarantine_id=rec.quarantine_id, tenant_id=rec.tenant_id,
                                             user_id=rec.user_id, text=evidence, category=cat,
                                             severity=a.severity.value, score=a.risk,
                                             source_platform=rec.source_platform,
                                             evidence=[f.evidence for f in a.findings
                                                       if f.evidence and f.detector not in ("HIDDEN_TRICK", "DLP")]))

    def _learned(self, f) -> bool:
        if (f.signature_id or "").startswith("falcon_"):
            return True
        if f.detector == "TIER3_VECTOR" and self.feed is not None:
            return any(v.vector_id == f.signature_id and v.source == "FALCON_LOOP" for v in self.feed.vectors.items)
        return False

    def list(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT record_json FROM quarantine ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for (rj,) in rows:
            d = json.loads(rj)
            d.pop("payload", None)
            out.append(d)
        return out

    def get(self, qid: str) -> dict | None:
        row = self._conn.execute("SELECT record_json FROM quarantine WHERE quarantine_id=?", (qid,)).fetchone()
        return json.loads(row[0]) if row else None

    def set_status(self, qid: str, status: str) -> bool:
        rec = self.get(qid)
        if not rec:
            return False
        rec["status"] = status
        with self._lock:
            self._conn.execute("UPDATE quarantine SET status=?, record_json=? WHERE quarantine_id=?",
                               (status, json.dumps(rec), qid))
            self._conn.commit()
        return True


def _offending_text(a) -> str:
    text = a.segment.text
    if len(text) <= 300:
        return text.strip()
    sents = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]
    evid = [f.evidence.lower() for f in a.findings if f.evidence]
    hits = [s for s in sents if any(e[:60] in s.lower() for e in evid if len(e) > 6)]
    return " ".join(hits[:2])[:300]
