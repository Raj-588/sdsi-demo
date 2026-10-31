"""Control plane API: endpoint agents (enroll / heartbeat / content / telemetry) and the fleet portal.

Agent routes    /v1/cp/agent/...     authenticated with X-Agent-Id + X-Agent-Token (issued at enrollment)
Portal routes   /v1/cp/...           authenticated with X-AI-EDR-Key when AI_EDR_API_KEY is set
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from ..demo_console.events import bus
from ..proxy_router.hook_webhook_controller import require_key
from ..settings import settings
from .content import ContentSigner, build_bundle, entries_sha, run_gate
from .store import RINGS, ControlPlaneStore

AUTO_ROLLBACK_AGENTS = int(os.getenv("AI_EDR_AUTO_ROLLBACK_AGENTS", "2"))
OFFLINE_AFTER_S = 90


class ControlPlane:
    """Owns the persistent Risk DB, the signing key and the release pipeline."""

    def __init__(self, data_dir=None, async_auto_release: bool = True):
        d = data_dir or settings.data_dir
        self.async_auto_release = async_auto_release
        self.store = ControlPlaneStore(d / "control_plane.db")
        self.signer = ContentSigner(d / "keys")
        self.auto_release = os.getenv("AI_EDR_AUTO_RELEASE", "1") == "1"
        self._release_lock = threading.Lock()
        self._bundle_cache: dict[tuple[int, str], dict] = {}
        self.store.seed_from_config()
        self.store.ensure_enroll_token(os.getenv("AI_EDR_ENROLL_TOKEN", "enroll-demo-default"), "default", "bootstrap")
        if not self.store.list_releases(1):
            rel = self.build_release("system:bootstrap", "Initial content from the seed Risk DB")
            if rel["status"] == "TESTED":
                self.store.set_release(rel["version"], "system:bootstrap", status="RELEASED", ring="GA")
        bus.add_listener(self._on_event)

    def close(self) -> None:
        if self._on_event in bus.listeners:
            bus.listeners.remove(self._on_event)

    # -- release pipeline --------------------------------------------------
    def build_release(self, actor: str, notes: str = "") -> dict:
        with self._release_lock:
            entries = self.store.active_entries()
            prev = next((r for r in self.store.list_releases(20) if r["status"] == "RELEASED"), None)
            gate = run_gate(entries, previous_recall=prev["gate"]["recall"] if prev else None)
            version = self.store.next_release_version()
            rel = self.store.create_release(version, entries, entries_sha(entries), gate, actor, notes)
        bus.publish("cp_release", {"version": version, "status": rel["status"], "recall": gate["recall"],
                                   "false_positives": gate["false_positives"], "reasons": gate["reasons"]})
        return rel

    def promote(self, version: int, ring: str, actor: str) -> dict:
        rel = self.store.get_release(version)
        if not rel:
            raise HTTPException(404, "release not found")
        if rel["status"] not in ("TESTED", "RELEASED"):
            raise HTTPException(409, f"release v{version} is {rel['status']} and cannot be promoted")
        if ring not in RINGS:
            raise HTTPException(400, f"ring must be one of {RINGS}")
        self.store.set_release(version, actor, status="RELEASED", ring=ring)
        bus.publish("cp_release", {"version": version, "status": "RELEASED", "ring": ring})
        return self.store.get_release(version)

    def rollback(self, version: int, actor: str, reason: str) -> dict:
        if not self.store.set_release(version, actor, status="ROLLED_BACK", reason=reason):
            raise HTTPException(404, "release not found")
        self._bundle_cache = {k: v for k, v in self._bundle_cache.items() if k[0] != version}
        bus.publish("cp_release", {"version": version, "status": "ROLLED_BACK", "reason": reason, "actor": actor})
        return self.store.get_release(version)

    def bundle_for(self, agent: dict) -> dict | None:
        rel = self.store.release_for_ring(agent["ring"])
        if rel is None:
            return None
        key = (rel["version"], agent["tenant_id"])
        if key not in self._bundle_cache:
            self._bundle_cache[key] = build_bundle(rel, agent["tenant_id"], self.signer)
        return self._bundle_cache[key]

    # -- learning loop: gateway promotions become tenant Risk DB entries ---------
    def _on_event(self, evt: dict) -> None:
        if evt["kind"] != "falcon_loop":
            return
        d = evt["data"]
        if d.get("action") not in ("PROMOTED", "PENDING_REVIEW"):
            return
        status = "ACTIVE" if d["action"] == "PROMOTED" else "PENDING_REVIEW"
        added = 0
        for text in d.get("learned_texts") or [d.get("text", "")]:
            if not text:
                continue
            if self.store.add_entry("VECTOR", text, d.get("category", "INSTRUCTION_OVERRIDE"), d.get("severity", "HIGH"),
                                    tier="TENANT", tenant_id=d.get("tenant_id"), source="LEARNED", status=status,
                                    notes=f"quarantine {d.get('quarantine_id')}", actor="system:learning-loop"):
                added += 1
                continue
            existing = self.store.find_entry("VECTOR", text, d.get("tenant_id"))
            if status == "ACTIVE" and existing and existing["status"] == "PENDING_REVIEW" and existing["source"] == "LEARNED":
                # a confident re-observation confirms a pending entry (same rule as the gateway's threat feed)
                self.store.set_entry_status(existing["id"], "ACTIVE", "system:learning-loop", "confirmed by re-observation")
                added += 1
        if added and status == "ACTIVE" and self.auto_release:
            # Learned content goes through the same gate and reaches CANARY endpoints first.
            if self.async_auto_release:
                threading.Thread(target=self._auto_release, daemon=True).start()
            else:
                self._auto_release()

    def _auto_release(self) -> None:
        rel = self.build_release("system:auto-release", "Learned entries from the gateway learning loop")
        if rel["status"] == "TESTED":
            self.promote(rel["version"], "CANARY", "system:auto-release")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class EnrollRequest(BaseModel):
    enroll_token: str
    hostname: str
    os: str
    os_version: str = ""
    agent_version: str = ""
    sensors: list[str] = Field(default_factory=list)
    ring: Optional[str] = None


class Heartbeat(BaseModel):
    content_version: int = 0
    health: str = "HEALTHY"
    agent_version: str = ""
    sensors: list[str] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)


class EventBatch(BaseModel):
    events: list[dict[str, Any]]


class EntryCreate(BaseModel):
    type: str
    pattern: str
    category: str
    severity: str = "HIGH"
    tier: str = "GLOBAL"
    tenant_id: Optional[str] = None
    status: str = "PENDING_REVIEW"
    dlp_kind: Optional[str] = None
    notes: str = ""


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

agent_router = APIRouter(prefix="/v1/cp/agent", tags=["control-plane: agent"])
portal_router = APIRouter(prefix="/v1/cp", tags=["control-plane: portal"], dependencies=[Depends(require_key)])


def _cp(request: Request) -> ControlPlane:
    return request.app.state.cp


def _agent(request: Request, x_agent_id: str = Header(...), x_agent_token: str = Header(...)) -> dict:
    agent = _cp(request).store.authenticate_agent(x_agent_id, x_agent_token)
    if not agent:
        raise HTTPException(401, "unknown agent or bad token")
    return agent


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


@agent_router.post("/enroll")
async def enroll(body: EnrollRequest, request: Request):
    cp = _cp(request)
    tenant = cp.store.tenant_for_enroll_token(body.enroll_token)
    if not tenant:
        raise HTTPException(401, "invalid enrollment token")
    agent, token = cp.store.enroll_agent(tenant, body.model_dump(), _ip(request))
    bus.publish("cp_agent", {"event": "enrolled", "agent_id": agent["agent_id"], "hostname": agent["hostname"]})
    return {"agent_id": agent["agent_id"], "agent_token": token, "tenant_id": tenant, "ring": agent["ring"],
            "mode": agent["mode"], "content_public_key": cp.signer.public_key_b64, "key_id": cp.signer.key_id}


@agent_router.post("/heartbeat")
async def heartbeat(body: Heartbeat, request: Request, agent: dict = Depends(_agent)):
    cp = _cp(request)
    cp.store.heartbeat(agent["agent_id"], body.model_dump(), _ip(request))
    agent = cp.store.get_agent(agent["agent_id"])
    bundle = cp.bundle_for(agent)
    return {"ring": agent["ring"], "mode": agent["mode"], "server_time": time.time(),
            "content": {"version": bundle["manifest"]["version"], "sha256": bundle["manifest"]["sha256"]} if bundle else None}


@agent_router.get("/content")
async def content(request: Request, agent: dict = Depends(_agent)):
    bundle = _cp(request).bundle_for(agent)
    if bundle is None:
        raise HTTPException(404, "no released content for this ring")
    return bundle


@agent_router.post("/events")
async def events(body: EventBatch, request: Request, agent: dict = Depends(_agent)):
    cp = _cp(request)
    stored = cp.store.add_events(agent, body.events[:500])
    for row in stored:
        bus.publish("agent_event", row)
        cp.store.record_hits(row["detail"].get("matched_entries", []) if isinstance(row["detail"], dict) else [])
        if row["kind"] in ("CONTENT_LOAD_FAILED", "SAFE_MODE") and row["content_version"]:
            v = row["content_version"]
            rel = cp.store.get_release(v)
            if rel and rel["status"] == "RELEASED" and cp.store.failing_agents_for_version(v) >= AUTO_ROLLBACK_AGENTS:
                cp.rollback(v, "system:auto-rollback", f"{AUTO_ROLLBACK_AGENTS}+ agents failed on content v{v}")
    return {"accepted": len(stored)}


# -- portal -----------------------------------------------------------------

@portal_router.get("/overview")
async def overview(request: Request):
    cp = _cp(request)
    agents = cp.store.list_agents()
    now = time.time()
    online = [a for a in agents if now - (a["last_seen"] or 0) < OFFLINE_AFTER_S]
    releases = cp.store.list_releases(10)
    current = next((r for r in releases if r["status"] == "RELEASED"), None)
    return {
        "agents": {"total": len(agents), "online": len(online),
                   "by_os": _count(agents, "os"), "by_ring": _count(agents, "ring"), "by_mode": _count(agents, "mode"),
                   "by_health": _count(online, "health"),
                   "content_versions": _count(agents, "content_version")},
        "events_24h": cp.store.event_stats(now - 86400),
        "risk_db": cp.store.entry_stats(),
        "content": {"current": current, "latest": releases[0] if releases else None},
        "gateway": request.app.state.guard.stats,
    }


def _count(rows: list[dict], key: str) -> dict:
    out: dict = {}
    for r in rows:
        out[str(r.get(key))] = out.get(str(r.get(key)), 0) + 1
    return out


@portal_router.get("/agents")
async def list_agents(request: Request):
    now = time.time()
    return [{**a, "online": now - (a["last_seen"] or 0) < OFFLINE_AFTER_S} for a in _cp(request).store.list_agents()]


@portal_router.get("/agents/{agent_id}")
async def get_agent(agent_id: str, request: Request):
    a = _cp(request).store.get_agent(agent_id)
    if not a:
        raise HTTPException(404, "not found")
    return {**a, "online": time.time() - (a["last_seen"] or 0) < OFFLINE_AFTER_S,
            "events": _cp(request).store.list_events(agent_id=agent_id, limit=100)}


@portal_router.post("/agents/{agent_id}")
async def update_agent(agent_id: str, request: Request, ring: Optional[str] = None, mode: Optional[str] = None):
    try:
        ok = _cp(request).store.update_agent(agent_id, "portal:admin", ring=ring, mode=mode)
    except ValueError as exc:
        raise HTTPException(400, f"bad value {exc}")
    if not ok:
        raise HTTPException(404, "not found")
    return _cp(request).store.get_agent(agent_id)


@portal_router.post("/enroll-tokens")
async def new_enroll_token(request: Request, tenant_id: str = "default"):
    return {"tenant_id": tenant_id, "enroll_token": _cp(request).store.create_enroll_token(tenant_id, "portal:admin")}


@portal_router.get("/events")
async def list_events(request: Request, agent_id: str = "", kind: str = "", severity: str = "", limit: int = 200):
    return _cp(request).store.list_events(agent_id=agent_id, kind=kind, severity=severity, limit=min(limit, 1000))


@portal_router.get("/risk-entries")
async def list_entries(request: Request, q: str = "", type: str = "", status: str = "", tier: str = "",
                       source: str = "", limit: int = 500):
    cp = _cp(request)
    return {"stats": cp.store.entry_stats(),
            "entries": cp.store.list_entries(q=q, type_=type, status=status, tier=tier, source=source, limit=limit)}


@portal_router.post("/risk-entries")
async def create_entry(body: EntryCreate, request: Request):
    try:
        e = _cp(request).store.add_entry(body.type, body.pattern, body.category, body.severity, tier=body.tier,
                                         tenant_id=body.tenant_id, source="ANALYST", status=body.status,
                                         dlp_kind=body.dlp_kind, notes=body.notes, actor="portal:analyst")
    except Exception as exc:  # bad regex, bad enum
        raise HTTPException(400, str(exc))
    if e is None:
        raise HTTPException(409, "an identical entry already exists")
    return e


@portal_router.post("/risk-entries/{entry_id}/status")
async def entry_status(entry_id: str, request: Request, status: str, reason: str = ""):
    try:
        ok = _cp(request).store.set_entry_status(entry_id, status, "portal:analyst", reason)
    except ValueError:
        raise HTTPException(400, "bad status")
    if not ok:
        raise HTTPException(404, "not found")
    return _cp(request).store.get_entry(entry_id)


@portal_router.post("/risk-entries/{entry_id}/false-positive")
async def entry_fp(entry_id: str, request: Request):
    if not _cp(request).store.report_false_positive(entry_id, "portal:analyst"):
        raise HTTPException(404, "not found")
    return _cp(request).store.get_entry(entry_id)


@portal_router.get("/releases")
async def list_releases(request: Request):
    return _cp(request).store.list_releases()


@portal_router.post("/releases")
async def create_release(request: Request, notes: str = ""):
    return _cp(request).build_release("portal:admin", notes)


@portal_router.post("/releases/{version}/promote")
async def promote_release(version: int, request: Request, ring: str):
    return _cp(request).promote(version, ring, "portal:admin")


@portal_router.post("/releases/{version}/rollback")
async def rollback_release(version: int, request: Request, reason: str = "manual rollback"):
    return _cp(request).rollback(version, "portal:admin", reason)


@portal_router.get("/audit")
async def audit(request: Request, limit: int = 200):
    return _cp(request).store.audit_log(limit)


@portal_router.get("/public-key")
async def public_key(request: Request):
    s = _cp(request).signer
    return {"algorithm": "Ed25519", "public_key": s.public_key_b64, "key_id": s.key_id}
