"""Local detection engine: the same AI-EDR pipeline as the gateway, loaded with signed Risk DB content.

Runs fully on the endpoint (CPU only, no cloud call), so file and command checks work offline and no
document content leaves the machine. Learning happens centrally; the endpoint only consumes signed bundles.
"""
from __future__ import annotations

import base64
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from agent.checkpointd.config import IS_WINDOWS, user_homes
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

_EXE = r"(?:\.exe)?"
EGRESS_TOOLS = re.compile(
    r"(^|[\s/\;|&(\"'])(curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|ftp|tftp|telnet|bitsadmin|certutil)" + _EXE + r"(\s|$)"
    r"|\b(invoke-webrequest|iwr|invoke-restmethod|irm|start-bitstransfer)\b|net\.webclient|system\.net\.http", re.I)
INLINE_NET = re.compile(r"(python[0-9.]*|node|perl|ruby)" + _EXE + r"\s+-[ce]\s.*(socket|urllib|requests|http\.client|fetch\(|net\.)", re.I)
DESTRUCTIVE = re.compile(
    r"\brm\s+-[a-z]*r[a-z]*f?\s+(~|/|\$HOME)(\s|/?$)|\bmkfs\b|\bdd\s+if=.*of=/dev/"
    r"|\b(rd|rmdir)\s+/s\s+/q\s+[a-z]:\\?(\s|$)|\bremove-item\b.*-recurse.*\s[a-z]:\\?(\s|$|\s*-)|\bformat(\.com)?\s+[a-z]:"
    r"|\bvssadmin" + _EXE + r"\s+delete\s+shadows|\bwbadmin" + _EXE + r"\s+delete|\bbcdedit" + _EXE + r"\b.*recoveryenabled\s+no"
    r"|\bcipher" + _EXE + r"\s+/w", re.I)
# Windows living-off-the-land binaries used to fetch or run payloads (alert: admins use some of them legitimately)
LOLBIN = re.compile(r"\bcertutil" + _EXE + r"\b.*-(urlcache|decode)|\bbitsadmin" + _EXE + r"\b.*/transfer|\bmshta" + _EXE + r"\s+(https?|javascript|vbscript):"
                    r"|\bregsvr32" + _EXE + r"\b.*/i:https?|\brundll32" + _EXE + r"\b.*javascript:|-(enc|encodedcommand)\s+[a-z0-9+/=]{20,}", re.I)
# ~, $HOME, %USERPROFILE%, $env:USERPROFILE ... -> <home>, so a credential path matches however the user's home is written
HOME_VARS = re.compile(r"(\$\{?HOME\}?|%USERPROFILE%|%HOMEDRIVE%%HOMEPATH%|\$\{?env:(USERPROFILE|HOME)\}?|~)(?=[/\\])", re.I)


@dataclass
class Judgement:
    verdict: str                     # BLOCK | ALERT | ALLOW
    severity: str
    category: str
    reason: str
    findings: list[dict] = field(default_factory=list)
    matched_entries: list[str] = field(default_factory=list)


class LocalEngine:
    def __init__(self, vault_dir: Path, protected_paths: list[Path], tenant: str = "default", windows: bool = IS_WINDOWS):
        self.guard = AIEDRGuard(data_dir=vault_dir)
        self.guard.vault.feed = None            # endpoints never learn locally; the control plane does, after the gate
        self.tenant = tenant
        self.windows = windows                  # case-insensitive paths, \ separators, %USERPROFILE%
        self.protected = self._protected_keys(protected_paths)
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
        normalized = self._norm(cmd)
        secret = next((shown for key, shown in self.protected if key in normalized), None)
        egress = bool(EGRESS_TOOLS.search(cmd) or INLINE_NET.search(cmd))
        if secret and egress:
            return Judgement("BLOCK", "CRITICAL", "TOOL_HIJACK",
                             f"AI agent tried to send credentials ({secret}) off the machine", [])
        if DESTRUCTIVE.search(cmd):
            return Judgement("BLOCK", "CRITICAL", "TOOL_HIJACK", "AI agent tried a destructive command", [])
        if secret:
            return Judgement("BLOCK", "HIGH", "SECRET_ACCESS", f"AI agent tried to read credentials ({secret})", [])
        if LOLBIN.search(cmd):
            return Judgement("ALERT", "HIGH", "TOOL_HIJACK", "AI agent used a living-off-the-land download/exec technique", [])
        v = self._inspect_tool_call(cmd, lineage)
        if v.verdict == VerdictType.BLOCKED:
            return self._from_verdict("BLOCK", v)
        if v.verdict in (VerdictType.AUDIT_FLAGGED, VerdictType.ALLOWED_SANITIZED):
            return self._from_verdict("ALERT", v)
        return Judgement("ALLOW", "NONE", "", "")

    def _norm(self, text: str) -> str:
        text = HOME_VARS.sub("<home>", text)
        return text.replace("\\", "/").lower() if self.windows else text

    def _protected_keys(self, paths: list[Path]) -> list[tuple[str, str]]:
        """(normalized substring, display form) for each protected path: absolute, and relative to its user's home."""
        homes = sorted({str(h) for h in user_homes() + [Path.home()]}, key=len, reverse=True)
        keys = []
        for p in map(str, paths):
            home = next((h for h in homes if p.startswith(h + os.sep) or p.startswith(h + "/")), None)
            rel = p[len(home) + 1:].replace("\\", "/") if home else None
            keys.append((self._norm(p), "~/" + rel if rel else p))
            if rel:
                keys.append((self._norm("<home>/" + rel), "~/" + rel))
        return keys

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


def split_cmd(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()
