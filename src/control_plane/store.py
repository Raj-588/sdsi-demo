"""Persistent AI Risk DB + fleet store for the control plane.

SQLite (WAL) here so the platform runs with zero dependencies; the schema is plain SQL and maps 1:1 to
Postgres for production (vectors move to Qdrant / pgvector, hot cache to Redis).

Tables
  risk_entries     every signature / regex / DLP pattern / threat vector, GLOBAL or per TENANT
  content_releases signed, gated content bundles and their rollout ring
  agents           enrolled endpoint agents (checkpointd)
  agent_events     detections and health telemetry reported by agents
  enroll_tokens    per-tenant enrollment secrets
  audit_log        every admin / analyst / system change
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from ..settings import load_signature_seed
from .taxonomy import classify, language_of

RINGS = ["CANARY", "EARLY", "BROAD", "GA"]          # rollout order; an agent in ring r gets releases promoted to >= r
ENTRY_TYPES = {"PHRASE", "REGEX", "DLP", "VECTOR"}
ENTRY_STATUSES = {"ACTIVE", "PENDING_REVIEW", "DISABLED", "REVERTED"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS risk_entries (
  id TEXT PRIMARY KEY, tier TEXT NOT NULL, tenant_id TEXT, type TEXT NOT NULL, pattern TEXT NOT NULL,
  category TEXT NOT NULL, severity TEXT NOT NULL, dlp_kind TEXT, language TEXT, owasp TEXT, atlas TEXT,
  source TEXT NOT NULL, status TEXT NOT NULL, confidence REAL, hits INTEGER DEFAULT 0, fp_reports INTEGER DEFAULT 0,
  notes TEXT, created_by TEXT, created_at REAL, updated_at REAL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_entry ON risk_entries(type, pattern, IFNULL(tenant_id, ''));
CREATE TABLE IF NOT EXISTS content_releases (
  version INTEGER PRIMARY KEY, created_at REAL, created_by TEXT, status TEXT, ring TEXT, entry_count INTEGER,
  sha256 TEXT, gate_json TEXT, entries_json TEXT, notes TEXT, updated_at REAL);
CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY, token_hash TEXT, tenant_id TEXT, hostname TEXT, os TEXT, os_version TEXT,
  agent_version TEXT, ring TEXT, mode TEXT, sensors_json TEXT, content_version INTEGER, health TEXT,
  stats_json TEXT, enrolled_at REAL, last_seen REAL, ip TEXT);
CREATE TABLE IF NOT EXISTS agent_events (
  id TEXT PRIMARY KEY, agent_id TEXT, tenant_id TEXT, hostname TEXT, ts REAL, kind TEXT, severity TEXT,
  action TEXT, category TEXT, title TEXT, process_json TEXT, detail_json TEXT, content_version INTEGER);
CREATE INDEX IF NOT EXISTS ix_events_ts ON agent_events(ts);
CREATE TABLE IF NOT EXISTS enroll_tokens (token_hash TEXT PRIMARY KEY, tenant_id TEXT, created_at REAL, label TEXT);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT,
  target TEXT, detail_json TEXT);
"""


def _h(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def _row(cur: sqlite3.Cursor, row: tuple) -> dict:
    out = {}
    for (name, *_), v in zip(cur.description, row):
        if name.endswith("_json"):
            out[name[:-5]] = json.loads(v) if v else None
        else:
            out[name] = v
    return out


class ControlPlaneStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # -- helpers ---------------------------------------------------------
    def _q(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._lock:
            cur = self._conn.execute(sql, args)
            return [_row(cur, r) for r in cur.fetchall()]

    def _x(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            return cur.rowcount

    def audit(self, actor: str, action: str, target: str = "", detail: dict | None = None) -> None:
        self._x("INSERT INTO audit_log(ts, actor, action, target, detail_json) VALUES (?,?,?,?,?)",
                (time.time(), actor, action, target, json.dumps(detail or {})))

    def audit_log(self, limit: int = 200) -> list[dict]:
        return self._q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    # -- risk entries ----------------------------------------------------
    def seed_from_config(self) -> int:
        """Import config/initial_risk_signatures.json as the GLOBAL tier (idempotent)."""
        if self._q("SELECT 1 FROM risk_entries LIMIT 1"):
            return 0
        seed = load_signature_seed()
        n = 0
        for s in seed.get("phrase_signatures", []):
            n += self.add_entry("PHRASE", s["pattern"], s["category"], s["severity"], source="SEED", entry_id=s["id"],
                                actor="system:seed", audit=False) is not None
        for s in seed.get("regex_signatures", []):
            n += self.add_entry("REGEX", s["pattern"], s["category"], s["severity"], source="SEED", entry_id=s["id"],
                                actor="system:seed", audit=False) is not None
        for s in seed.get("dlp_patterns", []):
            n += self.add_entry("DLP", s["pattern"], s["category"], "HIGH", source="SEED", entry_id=s["id"],
                                dlp_kind=s.get("kind"), actor="system:seed", audit=False) is not None
        for i, s in enumerate(seed.get("attack_corpus", [])):
            n += self.add_entry("VECTOR", s["text"], s["category"], "HIGH", source="SEED", entry_id=f"vec_seed_{i:03d}",
                                actor="system:seed", audit=False) is not None
        self.audit("system:seed", "risk_db.seed", "risk_entries", {"imported": n})
        return n

    def add_entry(self, type_: str, pattern: str, category: str, severity: str, *, tier: str = "GLOBAL",
                  tenant_id: str | None = None, source: str = "ANALYST", status: str = "ACTIVE",
                  confidence: float = 1.0, dlp_kind: str | None = None, notes: str = "", entry_id: str | None = None,
                  actor: str = "system", audit: bool = True) -> dict | None:
        if type_ not in ENTRY_TYPES or status not in ENTRY_STATUSES:
            raise ValueError(f"bad type/status {type_}/{status}")
        if type_ == "REGEX" or type_ == "DLP":
            import re
            re.compile(pattern)                      # reject broken patterns before they reach any endpoint
        tax = classify(category)
        now = time.time()
        eid = entry_id or f"{type_[:3].lower()}_{uuid.uuid4().hex[:10]}"
        try:
            self._x("""INSERT INTO risk_entries(id, tier, tenant_id, type, pattern, category, severity, dlp_kind, language,
                     owasp, atlas, source, status, confidence, notes, created_by, created_at, updated_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (eid, tier, tenant_id if tier == "TENANT" else None, type_, pattern, category, severity, dlp_kind,
                     language_of(pattern), tax["owasp"], tax["atlas"], source, status, confidence, notes, actor, now, now))
        except sqlite3.IntegrityError:
            return None                              # duplicate pattern for this tenant
        if audit:
            self.audit(actor, "risk_entry.create", eid, {"type": type_, "category": category, "status": status,
                                                         "tier": tier, "tenant_id": tenant_id})
        return self.get_entry(eid)

    def get_entry(self, eid: str) -> dict | None:
        r = self._q("SELECT * FROM risk_entries WHERE id=?", (eid,))
        return r[0] if r else None

    def find_entry(self, type_: str, pattern: str, tenant_id: str | None) -> dict | None:
        r = self._q("SELECT * FROM risk_entries WHERE type=? AND pattern=? AND IFNULL(tenant_id, '')=?",
                    (type_, pattern, tenant_id or ""))
        return r[0] if r else None

    def list_entries(self, *, q: str = "", type_: str = "", status: str = "", tier: str = "", source: str = "",
                     limit: int = 500) -> list[dict]:
        sql, args = "SELECT * FROM risk_entries WHERE 1=1", []
        for col, val in (("type", type_), ("status", status), ("tier", tier), ("source", source)):
            if val:
                sql += f" AND {col}=?"
                args.append(val)
        if q:
            sql += " AND (pattern LIKE ? OR category LIKE ? OR id LIKE ?)"
            args += [f"%{q}%"] * 3
        sql += " ORDER BY updated_at DESC LIMIT ?"
        return self._q(sql, (*args, limit))

    def set_entry_status(self, eid: str, status: str, actor: str, reason: str = "") -> bool:
        if status not in ENTRY_STATUSES:
            raise ValueError(status)
        ok = self._x("UPDATE risk_entries SET status=?, updated_at=? WHERE id=?", (status, time.time(), eid)) > 0
        if ok:
            self.audit(actor, "risk_entry.status", eid, {"status": status, "reason": reason})
        return ok

    def report_false_positive(self, eid: str, actor: str) -> bool:
        ok = self._x("UPDATE risk_entries SET fp_reports=fp_reports+1, updated_at=? WHERE id=?", (time.time(), eid)) > 0
        if ok:
            self.audit(actor, "risk_entry.false_positive", eid)
        return ok

    def record_hits(self, entry_ids: list[str]) -> None:
        for eid in entry_ids:
            self._x("UPDATE risk_entries SET hits=hits+1 WHERE id=?", (eid,))

    def active_entries(self) -> list[dict]:
        return self._q("SELECT * FROM risk_entries WHERE status='ACTIVE' ORDER BY id")

    def entry_stats(self) -> dict:
        by = lambda col: {r["k"]: r["n"] for r in self._q(f"SELECT {col} AS k, COUNT(*) AS n FROM risk_entries GROUP BY {col}")}
        return {"total": sum(by("type").values()), "by_type": by("type"), "by_status": by("status"),
                "by_source": by("source"), "by_tier": by("tier"), "by_category": by("category"), "by_owasp": by("owasp")}

    # -- content releases -----------------------------------------------
    def next_release_version(self) -> int:
        r = self._q("SELECT MAX(version) AS v FROM content_releases")
        return (r[0]["v"] or 0) + 1

    def create_release(self, version: int, entries: list[dict], sha: str, gate: dict, actor: str, notes: str) -> dict:
        status = "TESTED" if gate["passed"] else "GATE_FAILED"
        now = time.time()
        self._x("""INSERT INTO content_releases(version, created_at, created_by, status, ring, entry_count, sha256,
                 gate_json, entries_json, notes, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (version, now, actor, status, None, len(entries), sha, json.dumps(gate), json.dumps(entries), notes, now))
        self.audit(actor, "release.build", f"v{version}", {"status": status, "entries": len(entries),
                                                            "recall": gate.get("recall"), "fp": gate.get("false_positives")})
        return self.get_release(version)

    def get_release(self, version: int, with_entries: bool = False) -> dict | None:
        cols = "*" if with_entries else ("version, created_at, created_by, status, ring, entry_count, sha256, gate_json, "
                                         "notes, updated_at")
        r = self._q(f"SELECT {cols} FROM content_releases WHERE version=?", (version,))
        return r[0] if r else None

    def list_releases(self, limit: int = 50) -> list[dict]:
        return self._q("""SELECT version, created_at, created_by, status, ring, entry_count, sha256, gate_json, notes,
                          updated_at FROM content_releases ORDER BY version DESC LIMIT ?""", (limit,))

    def set_release(self, version: int, actor: str, *, status: str | None = None, ring: str | None = None,
                    reason: str = "") -> bool:
        rel = self.get_release(version)
        if not rel:
            return False
        self._x("UPDATE content_releases SET status=?, ring=?, updated_at=? WHERE version=?",
                (status or rel["status"], ring if ring is not None else rel["ring"], time.time(), version))
        self.audit(actor, "release.update", f"v{version}", {"status": status, "ring": ring, "reason": reason})
        return True

    def release_for_ring(self, ring: str) -> dict | None:
        """Newest RELEASED content an agent in `ring` may receive (CANARY sees releases first, GA last)."""
        rank = RINGS.index(ring)
        for rel in self._q("SELECT version, ring FROM content_releases WHERE status='RELEASED' ORDER BY version DESC"):
            if rel["ring"] in RINGS and RINGS.index(rel["ring"]) >= rank:
                return self.get_release(rel["version"], with_entries=True)
        return None

    # -- enrollment & agents --------------------------------------------
    def ensure_enroll_token(self, token: str, tenant_id: str, label: str = "default") -> None:
        if not self._q("SELECT 1 FROM enroll_tokens WHERE token_hash=?", (_h(token),)):
            self._x("INSERT INTO enroll_tokens VALUES (?,?,?,?)", (_h(token), tenant_id, time.time(), label))

    def create_enroll_token(self, tenant_id: str, actor: str) -> str:
        token = f"enr_{secrets.token_urlsafe(18)}"
        self._x("INSERT INTO enroll_tokens VALUES (?,?,?,?)", (_h(token), tenant_id, time.time(), f"by {actor}"))
        self.audit(actor, "enroll_token.create", tenant_id)
        return token

    def tenant_for_enroll_token(self, token: str) -> str | None:
        r = self._q("SELECT tenant_id FROM enroll_tokens WHERE token_hash=?", (_h(token),))
        return r[0]["tenant_id"] if r else None

    def enroll_agent(self, tenant_id: str, info: dict[str, Any], ip: str) -> tuple[dict, str]:
        token = secrets.token_urlsafe(32)
        agent_id = f"agt_{uuid.uuid4().hex[:12]}"
        now = time.time()
        # New endpoints start in the BROAD ring in enforce mode; admins move a few machines to CANARY / EARLY.
        ring = info.get("ring") if info.get("ring") in RINGS else "BROAD"
        self._x("""INSERT INTO agents(agent_id, token_hash, tenant_id, hostname, os, os_version, agent_version, ring, mode,
                 sensors_json, content_version, health, stats_json, enrolled_at, last_seen, ip)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (agent_id, _h(token), tenant_id, info.get("hostname", "?"), info.get("os", "?"), info.get("os_version", ""),
                 info.get("agent_version", ""), ring, "ENFORCE", json.dumps(info.get("sensors", [])), 0, "HEALTHY",
                 json.dumps({}), now, now, ip))
        self.audit(f"agent:{agent_id}", "agent.enroll", agent_id, {"hostname": info.get("hostname"), "tenant": tenant_id})
        return self.get_agent(agent_id), token

    def authenticate_agent(self, agent_id: str, token: str) -> dict | None:
        r = self._q("SELECT * FROM agents WHERE agent_id=? AND token_hash=?", (agent_id, _h(token)))
        return r[0] if r else None

    def heartbeat(self, agent_id: str, hb: dict[str, Any], ip: str) -> None:
        self._x("""UPDATE agents SET last_seen=?, content_version=?, health=?, stats_json=?, sensors_json=?, ip=?,
                   agent_version=? WHERE agent_id=?""",
                (time.time(), int(hb.get("content_version") or 0), hb.get("health", "HEALTHY"),
                 json.dumps(hb.get("stats", {})), json.dumps(hb.get("sensors", [])), ip, hb.get("agent_version", ""),
                 agent_id))

    def get_agent(self, agent_id: str) -> dict | None:
        r = self._q("SELECT * FROM agents WHERE agent_id=?", (agent_id,))
        if not r:
            return None
        a = r[0]
        a.pop("token_hash", None)
        return a

    def list_agents(self) -> list[dict]:
        out = self._q("SELECT * FROM agents ORDER BY last_seen DESC")
        for a in out:
            a.pop("token_hash", None)
        return out

    def update_agent(self, agent_id: str, actor: str, *, ring: str | None = None, mode: str | None = None) -> bool:
        if ring is not None and ring not in RINGS:
            raise ValueError(ring)
        if mode is not None and mode not in ("ENFORCE", "MONITOR"):
            raise ValueError(mode)
        a = self.get_agent(agent_id)
        if not a:
            return False
        self._x("UPDATE agents SET ring=?, mode=? WHERE agent_id=?", (ring or a["ring"], mode or a["mode"], agent_id))
        self.audit(actor, "agent.update", agent_id, {"ring": ring, "mode": mode})
        return True

    # -- telemetry -------------------------------------------------------
    def add_events(self, agent: dict, events: list[dict]) -> list[dict]:
        stored = []
        for e in events:
            row = {"id": e.get("id") or f"evt_{uuid.uuid4().hex[:12]}", "agent_id": agent["agent_id"],
                   "tenant_id": agent["tenant_id"], "hostname": agent["hostname"], "ts": float(e.get("ts") or time.time()),
                   "kind": e.get("kind", "INFO"), "severity": e.get("severity", "LOW"), "action": e.get("action", "OBSERVED"),
                   "category": e.get("category", ""), "title": e.get("title", "")[:300],
                   "process": e.get("process") or {}, "detail": e.get("detail") or {},
                   "content_version": int(e.get("content_version") or 0)}
            try:
                self._x("""INSERT INTO agent_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (row["id"], row["agent_id"], row["tenant_id"], row["hostname"], row["ts"], row["kind"],
                         row["severity"], row["action"], row["category"], row["title"], json.dumps(row["process"]),
                         json.dumps(row["detail"]), row["content_version"]))
            except sqlite3.IntegrityError:
                continue                              # agent retried a batch it already delivered
            stored.append(row)
        return stored

    def list_events(self, *, agent_id: str = "", kind: str = "", severity: str = "", limit: int = 200) -> list[dict]:
        sql, args = "SELECT * FROM agent_events WHERE 1=1", []
        for col, val in (("agent_id", agent_id), ("kind", kind), ("severity", severity)):
            if val:
                sql += f" AND {col}=?"
                args.append(val)
        sql += " ORDER BY ts DESC LIMIT ?"
        return self._q(sql, (*args, limit))

    def failing_agents_for_version(self, version: int) -> int:
        r = self._q("""SELECT COUNT(DISTINCT agent_id) AS n FROM agent_events
                       WHERE kind IN ('CONTENT_LOAD_FAILED', 'SAFE_MODE') AND content_version=?""", (version,))
        return r[0]["n"]

    def event_stats(self, since: float) -> dict:
        rows = self._q("SELECT kind, action, severity, ts FROM agent_events WHERE ts>=?", (since,))
        by = lambda key: {k: sum(1 for r in rows if r[key] == k) for k in sorted({r[key] for r in rows})}
        buckets: dict[int, int] = {}
        for r in rows:
            b = int(r["ts"] // 3600 * 3600)
            buckets[b] = buckets.get(b, 0) + 1
        return {"total": len(rows), "by_kind": by("kind"), "by_action": by("action"), "by_severity": by("severity"),
                "hourly": sorted(buckets.items())}
