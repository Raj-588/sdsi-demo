"""Local detection engine: the same AI-EDR pipeline as the gateway, loaded with signed Risk DB content.

Runs fully on the endpoint (CPU only, no cloud call), so file and command checks work offline and no
document content leaves the machine. Learning happens centrally; the endpoint only consumes signed bundles.
"""
from __future__ import annotations

import base64
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from src.ai_edr_guard.pipeline_orchestrator import AIEDRGuard
from src.control_plane.content import verify_bundle
from src.schemas.canonical import (
    ActorContext,
    CanonicalAIEDRRequest,
    IndirectAttachment,
    InputVectors,
    InspectionStage,
    PolicyMode,
    PolicyProfile,
    ProposedToolCall,
    SourcePlatform,
    VerdictType,
)

EGRESS_TOOLS = re.compile(r"(^|[\s/;|&(])(curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|ftp|tftp|telnet)(\s|$)")
INLINE_NET = re.compile(r"(python[0-9.]*|node|perl|ruby)\s+-[ce]\s.*(socket|urllib|requests|http\.client|fetch\(|net\.)")
DESTRUCTIVE = re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\s+(~|/|\$HOME)(\s|/?$)|\bmkfs\b|\bdd\s+if=.*of=/dev/")


@dataclass
class Judgement:
    verdict: str                     # BLOCK | ALERT | ALLOW
    severity: str
    category: str
    reason: str
    findings: list[dict] = field(default_factory=list)
    matched_entries: list[str] = field(default_factory=list)


class LocalEngine:
    def __init__(self, vault_dir: Path, protected_paths: list[Path], tenant: str = "default"):
        self.guard = AIEDRGuard(data_dir=vault_dir)
        self.guard.vault.feed = None            # endpoints never learn locally; the control plane does, after the gate
        self.tenant = tenant
        self.protected = [str(p) for p in protected_paths]
        self.content_version = 0
        self.content_entries = 0

    # -- content -----------------------------------------------------------
    def apply_bundle(self, bundle: dict, public_key_b64: str) -> int:
        """Verify and hot-swap content. Raises (and keeps the previous content) on any signature or hash failure."""
        entries = verify_bundle(bundle, public_key_b64)
        self.guard.signatures.load_entries(entries)
        self.guard.vectors.load_entries(entries)
        self.content_version = bundle["manifest"]["version"]
        self.content_entries = len(entries)
        return self.content_version

    # -- exec checkpoint ---------------------------------------------------
    def judge_exec(self, cmdline: list[str], lineage: list[dict]) -> Judgement:
        cmd = " ".join(cmdline)
        expanded = cmd.replace("~/", str(Path.home()) + "/").replace("$HOME", str(Path.home()))
        secret = next((p for p in self.protected if p in expanded), None)
        egress = bool(EGRESS_TOOLS.search(cmd) or INLINE_NET.search(cmd))
        if secret and egress:
            return Judgement("BLOCK", "CRITICAL", "TOOL_HIJACK",
                             f"AI agent tried to send credentials ({_short(secret)}) off the machine", [])
        if DESTRUCTIVE.search(cmd):
            return Judgement("BLOCK", "CRITICAL", "TOOL_HIJACK", "AI agent tried a destructive command", [])
        if secret:
            return Judgement("BLOCK", "HIGH", "SECRET_ACCESS", f"AI agent tried to read credentials ({_short(secret)})", [])
        v = self._inspect_tool_call(cmd, lineage)
        if v.verdict == VerdictType.BLOCKED:
            return self._from_verdict("BLOCK", v)
        if v.verdict in (VerdictType.AUDIT_FLAGGED, VerdictType.ALLOWED_SANITIZED):
            return self._from_verdict("ALERT", v)
        return Judgement("ALLOW", "NONE", "", "")

    def _inspect_tool_call(self, cmd: str, lineage: list[dict]):
        req = CanonicalAIEDRRequest(
            source_platform=SourcePlatform.CLAUDE_IDE, inspection_stage=InspectionStage.PRE_TOOL_EXECUTION,
            actor_context=ActorContext(tenant_id=self.tenant, user_id=lineage[0].get("user", "?") if lineage else "?",
                                       client_ide_or_app="checkpointd:exec"),
            input_vectors=InputVectors(proposed_tool_calls=[ProposedToolCall(name="exec", arguments={"command": cmd})]))
        return self.guard.inspect(req)

    # -- file checkpoint ---------------------------------------------------
    def scan_file(self, path: Path, data: bytes) -> tuple[Judgement, str | None]:
        """Returns the judgement and, when the file can be cleaned, the sanitized text to serve instead."""
        req = CanonicalAIEDRRequest(
            source_platform=SourcePlatform.CLAUDE_IDE, inspection_stage=InspectionStage.PRE_LLM_INDIRECT_FILE,
            actor_context=ActorContext(tenant_id=self.tenant, user_id="endpoint", client_ide_or_app="checkpointd:file"),
            input_vectors=InputVectors(indirect_attachments=[IndirectAttachment(
                filename=path.name, content_base64=base64.b64encode(data).decode(),
                mime_type="application/octet-stream", source_path=str(path))]),
            policy_profile=PolicyProfile(mode=PolicyMode.STRIP_AND_SANITIZE))
        v = self.guard.inspect(req)
        if v.verdict == VerdictType.ALLOWED_SANITIZED:
            text = "\n\n".join(e.sanitized_text for e in v.sanitization)
            return self._from_verdict("SANITIZE", v), text
        if v.verdict == VerdictType.BLOCKED:
            return self._from_verdict("BLOCK", v), None
        if v.verdict == VerdictType.AUDIT_FLAGGED:
            return self._from_verdict("ALERT", v), None
        return Judgement("ALLOW", "NONE", "", ""), None

    def _from_verdict(self, action: str, v) -> Judgement:
        findings = [{"detector": f.detector, "category": f.category, "severity": f.severity.value,
                     "score": round(f.score, 3), "evidence": (f.evidence or "")[:200], "signature_id": f.signature_id}
                    for f in v.findings[:10]]
        top = v.findings[0].category if v.findings else "PROMPT_INJECTION"
        return Judgement(action, v.severity.value, top, v.reason, findings,
                         sorted({f.signature_id for f in v.findings if f.signature_id}))


def _short(p: str) -> str:
    return p.replace(str(Path.home()), "~")


def split_cmd(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()
