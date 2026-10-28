"""CanonicalAIEDRRequest and Verdict schemas (spec §3.2, architecture §4.2)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class SourcePlatform(str, Enum):
    OPENAI = "OPENAI"
    GEMINI = "GEMINI"
    CLAUDE_IDE = "CLAUDE_IDE"
    ANTIGRAVITY_IDE = "ANTIGRAVITY_IDE"
    SAMSUNG_FABRIX = "SAMSUNG_FABRIX"
    SAMSUNG_AIPRO = "SAMSUNG_AIPRO"


class InspectionStage(str, Enum):
    PRE_LLM_DIRECT = "PRE_LLM_DIRECT"
    PRE_LLM_INDIRECT_FILE = "PRE_LLM_INDIRECT_FILE"
    PRE_RAG_CHUNK = "PRE_RAG_CHUNK"
    PRE_TOOL_EXECUTION = "PRE_TOOL_EXECUTION"


class PolicyMode(str, Enum):
    BLOCK_AND_QUARANTINE = "BLOCK_AND_QUARANTINE"
    STRIP_AND_SANITIZE = "STRIP_AND_SANITIZE"
    AUDIT_ONLY = "AUDIT_ONLY"


class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(self.value)


SEVERITY_SCORE = {
    Severity.NONE: 0.0,
    Severity.LOW: 0.35,
    Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.8,
    Severity.CRITICAL: 0.97,
}


class VerdictType(str, Enum):
    ALLOWED = "ALLOWED"
    ALLOWED_SANITIZED = "ALLOWED_SANITIZED"
    BLOCKED = "BLOCKED"
    AUDIT_FLAGGED = "AUDIT_FLAGGED"


class SegmentKind(str, Enum):
    USER_PROMPT = "USER_PROMPT"
    SYSTEM = "SYSTEM"
    FILE = "FILE"
    RAG_CHUNK = "RAG_CHUNK"
    TOOL_RESULT = "TOOL_RESULT"
    TOOL_CALL = "TOOL_CALL"
    METADATA = "METADATA"
    DECODED = "DECODED"


class Trust(str, Enum):
    TRUSTED = "TRUSTED"
    SEMI_TRUSTED = "SEMI_TRUSTED"
    UNTRUSTED = "UNTRUSTED"


# ----------------------------------------------------------------------------
# Canonical request (spec §3.2)
# ----------------------------------------------------------------------------

class ActorContext(BaseModel):
    user_id: str = "anonymous"
    tenant_id: str = "default"
    client_ide_or_app: str = "unknown"
    session_id: str = Field(default_factory=lambda: f"sess_{uuid.uuid4().hex[:10]}")


class IndirectAttachment(BaseModel):
    filename: str
    mime_type: str = "text/plain"
    extracted_raw_text: str = ""
    hidden_layer_anomalies: list[str] = Field(default_factory=list)
    suspicious_spans: list[str] = Field(default_factory=list)
    # Base64 content may be supplied instead of extracted text; the scanner fills the rest.
    content_base64: Optional[str] = None
    source_path: Optional[str] = None      # JSON pointer into the original provider payload
    kind: SegmentKind = SegmentKind.FILE    # FILE | RAG_CHUNK | TOOL_RESULT


class ProposedToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    source_path: Optional[str] = None


class InputVectors(BaseModel):
    direct_user_prompt: str = ""
    system_instructions: str = ""
    indirect_attachments: list[IndirectAttachment] = Field(default_factory=list)
    proposed_tool_calls: list[ProposedToolCall] = Field(default_factory=list)
    user_prompt_source_path: Optional[str] = None


class PolicyProfile(BaseModel):
    mode: Optional[PolicyMode] = None      # None = take from tenant policy
    enable_falcon_technique: bool = True


class CanonicalAIEDRRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_platform: SourcePlatform = SourcePlatform.OPENAI
    inspection_stage: InspectionStage = InspectionStage.PRE_LLM_DIRECT
    actor_context: ActorContext = Field(default_factory=ActorContext)
    input_vectors: InputVectors = Field(default_factory=InputVectors)
    policy_profile: PolicyProfile = Field(default_factory=PolicyProfile)


# ----------------------------------------------------------------------------
# Internal pipeline types
# ----------------------------------------------------------------------------

class Segment(BaseModel):
    segment_id: str
    source_path: Optional[str] = None
    kind: SegmentKind
    trust: Trust
    text: str                               # normalized / de-obfuscated text used for matching
    raw_text: str                           # as received
    label: str = ""                         # filename, tool name, etc.
    anomalies: list[str] = Field(default_factory=list)
    hidden_spans: list[str] = Field(default_factory=list)   # text invisible to a human reader
    parent_id: Optional[str] = None         # for DECODED segments


class Finding(BaseModel):
    segment_id: str
    detector: str                           # TIER1_SIGNATURE | TIER1_REGEX | DLP | TIER2_CLASSIFIER | TIER2_IOA | TIER3_VECTOR | HIDDEN_TRICK
    category: str
    severity: Severity
    score: float
    evidence: str = ""
    span: Optional[tuple[int, int]] = None
    signature_id: Optional[str] = None
    segment_kind: Optional[SegmentKind] = None
    trust: Optional[Trust] = None


class SanitizationEdit(BaseModel):
    segment_id: str
    source_path: Optional[str]
    original_text: str
    sanitized_text: str
    removed_spans: list[str]


class Verdict(BaseModel):
    request_id: str
    verdict: VerdictType
    risk_score: float
    severity: Severity
    policy_mode: PolicyMode
    source_platform: SourcePlatform
    tenant_id: str
    user_id: str
    findings: list[Finding] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    sanitization: list[SanitizationEdit] = Field(default_factory=list)
    sanitized_payload: Optional[Any] = None
    quarantine_id: Optional[str] = None
    reason: str = ""
    latency_ms: dict[str, float] = Field(default_factory=dict)
    policy_version: int = 1
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
