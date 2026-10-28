"""Quarantine forensic record models (architecture §4.5 Quarantine Vault)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from .canonical import Finding


class QuarantineRecord(BaseModel):
    quarantine_id: str
    request_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    user_id: str
    session_id: str
    source_platform: str
    inspection_stage: str
    severity: str
    risk_score: float
    payload_sha256: str
    file_hashes: dict[str, str] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    matched_signatures: list[str] = Field(default_factory=list)
    falcon_ioa_score: float = 0.0
    policy_version: int = 1
    status: str = "QUARANTINED"             # QUARANTINED | RELEASED | CONFIRMED_MALICIOUS
    payload: Optional[Any] = None           # only returned to analysts with access


class FalconCandidate(BaseModel):
    """A trapped attack proposed for promotion into the AI Risk Database."""
    quarantine_id: str
    tenant_id: str
    user_id: str
    text: str
    category: str
    severity: str
    score: float
    source_platform: str
    evidence: list[str] = Field(default_factory=list)   # what the detectors actually flagged
