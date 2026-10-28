"""Stage 3 — AI-EDR Security Guard pipeline orchestrator.

CanonicalAIEDRRequest
  -> Stage 1 collectors (segments, file scanning)
  -> 3.1 HiddenTrickAnalyzer
  -> 3.2 FalconEngine Tier 1 / 2 / 3 per segment
  -> 3.3 DecisionAndRemediationEngine -> CDR strip | Quarantine Vault (+ Falcon Loop)
  -> Verdict (+ sanitized provider payload)
"""
from __future__ import annotations

import time
from typing import Any

from ..collectors.direct_prompt_collector import build_segments
from ..demo_console.events import bus
from ..risk_database.falcon_threat_feed import FalconThreatFeed
from ..risk_database.signature_store import SignatureStore
from ..risk_database.vector_threat_db import VectorThreatDB
from ..schemas.canonical import (
    CanonicalAIEDRRequest,
    PolicyMode,
    SanitizationEdit,
    SegmentKind,
    Severity,
    Verdict,
    VerdictType,
)
from ..settings import policy_store
from . import hidden_trick_analyzer
from .command_stripper_cdr import CommandStripper
from .decision_engine import Decision, decide
from .falcon_engine import FalconEngine, SegmentAssessment
from .quarantine_vault import QuarantineVault


class AIEDRGuard:
    def __init__(self, data_dir=None):
        self.signatures = SignatureStore()
        self.vectors = VectorThreatDB()
        self.feed = FalconThreatFeed(self.signatures, self.vectors)
        self.engine = FalconEngine(self.signatures, self.vectors)
        self.stripper = CommandStripper(self.engine)
        self.vault = QuarantineVault(data_dir, feed=self.feed)
        self.stats = {"requests": 0, "blocked": 0, "sanitized": 0, "audit": 0, "allowed": 0, "tokens_saved_est": 0}

    def inspect(self, req: CanonicalAIEDRRequest, raw_payload: Any = None, adapter=None) -> Verdict:
        t_start = time.perf_counter()
        tenant = req.actor_context.tenant_id
        policy = policy_store.for_tenant(tenant)
        mode = req.policy_profile.mode or PolicyMode(policy.get("mode", "STRIP_AND_SANITIZE"))
        falcon_on = req.policy_profile.enable_falcon_technique and policy.get("enable_falcon_technique", True)
        timings: dict[str, float] = {}

        # Stage 1 ----------------------------------------------------------------
        t = time.perf_counter()
        segments = build_segments(req)
        timings["collect_ms"] = (time.perf_counter() - t) * 1000

        # Stage 3.1 --------------------------------------------------------------
        t = time.perf_counter()
        segments = hidden_trick_analyzer.analyze(segments)
        timings["hidden_tricks_ms"] = (time.perf_counter() - t) * 1000

        # Stage 3.2 --------------------------------------------------------------
        assessments: list[SegmentAssessment] = []
        session = req.actor_context.session_id
        try:
            for seg in segments:
                if not falcon_on and seg.kind != SegmentKind.SYSTEM:
                    policy = {**policy, "thresholds": {"classifier": 1.01, "vector_similarity": 1.01}}
                assessments.append(self.engine.evaluate(seg, policy, session))
        except Exception as exc:
            return self._fail(req, policy, mode, exc, t_start)
        for key in ("tier1_ms", "tier2_ms", "tier3_ms"):
            timings[key] = round(sum(a.timings.get(key, 0.0) for a in assessments), 3)

        # Record the agent process tree: untrusted segments that tried to give orders taint the session.
        for a in assessments:
            if a.segment.kind in (SegmentKind.FILE, SegmentKind.RAG_CHUNK, SegmentKind.TOOL_RESULT,
                                  SegmentKind.METADATA, SegmentKind.DECODED):
                tainted = a.ioa_score >= 0.5 or a.severity.rank >= Severity.MEDIUM.rank
                self.engine.process_tree.record(session, a.segment.kind.value, tainted, a.segment.label)
            elif a.segment.kind == SegmentKind.TOOL_CALL:
                self.engine.process_tree.record(session, "TOOL_CALL", False, a.segment.label)

        # Stage 3.3 --------------------------------------------------------------
        t = time.perf_counter()
        decision = decide(assessments, mode, policy)
        edits: list[SanitizationEdit] = []
        if decision.verdict == VerdictType.ALLOWED_SANITIZED:
            decision, edits = self._sanitize(decision, assessments)
        timings["decision_ms"] = (time.perf_counter() - t) * 1000

        findings = [f for a in assessments for f in a.findings]
        findings.sort(key=lambda f: (-f.severity.rank, -f.score))
        risk = max((a.risk for a in assessments), default=0.0)
        verdict = Verdict(
            request_id=req.request_id, verdict=decision.verdict, risk_score=round(risk, 4),
            severity=decision.severity, policy_mode=mode, source_platform=req.source_platform,
            tenant_id=tenant, user_id=req.actor_context.user_id, findings=findings,
            anomalies=sorted({x for a in assessments for x in a.segment.anomalies}),
            sanitization=edits, reason=decision.reason, policy_version=policy_store.version,
        )

        if verdict.verdict == VerdictType.BLOCKED:
            rec = self.vault.trap(req, verdict, assessments, raw_payload)
            verdict.quarantine_id = rec.quarantine_id
        elif verdict.verdict == VerdictType.ALLOWED_SANITIZED and adapter is not None and raw_payload is not None:
            verdict.sanitized_payload = adapter.apply_sanitization(raw_payload, edits)

        timings["total_ms"] = (time.perf_counter() - t_start) * 1000
        verdict.latency_ms = {k: round(v, 3) for k, v in timings.items()}
        self._record(req, verdict, segments)
        return verdict

    # ------------------------------------------------------------------
    def _sanitize(self, decision: Decision, assessments: list[SegmentAssessment]):
        by_id = {a.segment.segment_id: a for a in assessments}
        edits: list[SanitizationEdit] = []
        for root_id in decision.strip_segment_ids:
            root = by_id[root_id]
            # Evidence found in child segments (hidden layer, metadata, decoded) is stripped from the parent too.
            extra = []
            for a in assessments:
                if a.segment.parent_id == root_id and a.severity.rank >= Severity.MEDIUM.rank:
                    if a.segment.kind == SegmentKind.METADATA and "#hidden-layer" not in a.segment.label:
                        continue  # metadata is not part of the body; it is dropped with the binary
                    extra.append(a.segment.raw_text)
            res = self.stripper.strip(root.segment, extra_spans=extra)
            if res.residual_risk >= 0.7:
                return Decision(VerdictType.BLOCKED, Severity.HIGH,
                                f"Sanitization of '{root.segment.label}' left residual risk {res.residual_risk}; escalated to block."), []
            edits.append(SanitizationEdit(segment_id=root_id, source_path=root.segment.source_path,
                                          original_text=root.segment.raw_text[:4000], sanitized_text=res.wrapped_text,
                                          removed_spans=res.removed))
        return decision, edits

    def _fail(self, req, policy, mode, exc, t_start) -> Verdict:
        fail_closed = policy.get("fail_mode", "CLOSED") == "CLOSED"
        v = Verdict(request_id=req.request_id,
                    verdict=VerdictType.BLOCKED if fail_closed else VerdictType.AUDIT_FLAGGED,
                    risk_score=0.0, severity=Severity.MEDIUM, policy_mode=mode, source_platform=req.source_platform,
                    tenant_id=req.actor_context.tenant_id, user_id=req.actor_context.user_id,
                    reason=f"Detector failure ({type(exc).__name__}); fail_mode={policy.get('fail_mode', 'CLOSED')}",
                    latency_ms={"total_ms": (time.perf_counter() - t_start) * 1000})
        bus.publish("detector_error", {"error": repr(exc), "request_id": req.request_id})
        return v

    def _record(self, req: CanonicalAIEDRRequest, v: Verdict, segments) -> None:
        self.stats["requests"] += 1
        key = {VerdictType.BLOCKED: "blocked", VerdictType.ALLOWED_SANITIZED: "sanitized",
               VerdictType.AUDIT_FLAGGED: "audit", VerdictType.ALLOWED: "allowed"}[v.verdict]
        self.stats[key] += 1
        if v.verdict == VerdictType.BLOCKED:
            self.stats["tokens_saved_est"] += sum(len(s.raw_text) for s in segments) // 4
        prompt = req.input_vectors.direct_user_prompt
        bus.publish("verdict", {
            "request_id": v.request_id, "verdict": v.verdict.value, "severity": v.severity.value,
            "risk": v.risk_score, "platform": v.source_platform.value, "stage": req.inspection_stage.value,
            "tenant": v.tenant_id, "user": v.user_id, "client": req.actor_context.client_ide_or_app,
            "mode": v.policy_mode.value, "reason": v.reason, "quarantine_id": v.quarantine_id,
            "prompt": prompt[-400:], "attachments": [a.filename for a in req.input_vectors.indirect_attachments],
            "anomalies": v.anomalies,
            "findings": [f.model_dump(mode="json", include={"detector", "category", "severity", "score", "evidence"})
                         for f in v.findings[:12]],
            "sanitization": [{"segment": e.segment_id, "removed": e.removed_spans[:6],
                              "after": e.sanitized_text[:1200], "before": e.original_text[:1200]} for e in v.sanitization],
            "latency_ms": v.latency_ms,
        })
