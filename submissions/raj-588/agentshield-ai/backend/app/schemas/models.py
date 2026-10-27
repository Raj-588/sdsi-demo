"""Pydantic v2 schemas for API validation and internal typed contracts."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    AgentMode,
    Decision,
    ExecutionStatus,
    ReasonCode,
    TaskStatus,
)


# --------------------------------------------------------------------------- #
# Tool calls
# --------------------------------------------------------------------------- #
class ToolCall(BaseModel):
    """A proposed tool call. May originate from the LLM — therefore untrusted."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(..., max_length=64)
    operation: str = Field(..., max_length=32)
    resource: str | None = Field(default=None, max_length=128)
    arguments: dict = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Tasks
# --------------------------------------------------------------------------- #
class TaskPermissionIn(BaseModel):
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_operations: list[str] = Field(default_factory=list)
    allowed_resources: list[str] = Field(default_factory=list)
    argument_constraints: dict = Field(default_factory=dict)
    sensitive_approved: bool = False


class TaskCreate(BaseModel):
    """Trusted task creation. For the MVP the server binds user_id itself;
    any client-supplied identity claim is informational only."""

    model_config = ConfigDict(extra="forbid")

    template_id: str | None = Field(default=None, max_length=64)
    original_request: str = Field(..., max_length=4000)
    permission: TaskPermissionIn | None = None
    ttl_minutes: int | None = Field(default=None, ge=1, le=1440)


class TaskPermissionOut(TaskPermissionIn):
    model_config = ConfigDict(from_attributes=True)


class TaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    original_request: str
    status: TaskStatus
    created_at: datetime
    expires_at: datetime
    permission: TaskPermissionOut | None = None


# --------------------------------------------------------------------------- #
# Gateway / IntentLock
# --------------------------------------------------------------------------- #
class GatewayEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., max_length=64)
    call: ToolCall
    execute: bool = True
    correlation_id: str | None = Field(default=None, max_length=64)


class PolicyDecision(BaseModel):
    decision: Decision
    reason_code: ReasonCode
    explanation: str


class GatewayEvaluateResponse(BaseModel):
    decision: Decision
    reason_code: ReasonCode
    explanation: str
    execution_status: ExecutionStatus
    result: dict | None = None
    correlation_id: str
    audit_event_id: str
    # Set when the decision is REQUIRES_APPROVAL: the pending approval to resolve.
    approval_request_id: str | None = None


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    task_id: str
    tool: str
    resource: str | None
    arguments: dict
    approved: bool
    consumed: bool
    approved_by: str | None


# --------------------------------------------------------------------------- #
# Agent
# --------------------------------------------------------------------------- #
class AgentRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., max_length=64)
    scenario_id: str | None = Field(default=None, max_length=64)
    document_name: str | None = Field(default=None, max_length=128)
    document_content: str | None = Field(default=None, max_length=20000)
    user_request: str | None = Field(default=None, max_length=4000)


class EvaluatedCall(BaseModel):
    call: ToolCall
    decision: Decision
    reason_code: ReasonCode
    explanation: str
    execution_status: ExecutionStatus
    result: dict | None = None


class AgentRunResponse(BaseModel):
    task_id: str
    agent_mode: AgentMode
    user_response: str
    proposed_calls: list[ToolCall]
    evaluated_calls: list[EvaluatedCall]
    correlation_id: str


# --------------------------------------------------------------------------- #
# Audit / metrics / status
# --------------------------------------------------------------------------- #
class AuditRecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    correlation_id: str
    timestamp: datetime
    task_id: str | None
    user_id: str | None
    agent_id: str | None
    tool: str
    operation: str
    resource: str | None
    decision: Decision
    reason_code: ReasonCode
    explanation: str
    execution_status: ExecutionStatus


class DashboardMetrics(BaseModel):
    total_proposed: int
    allowed: int
    denied: int
    requires_approval: int
    executed: int
    blocked: int
    recent_events: list[AuditRecordOut]


class LLMStatus(BaseModel):
    ollama_available: bool  # retained for compatibility; true when any provider is live
    provider: str
    model: str
    mode: AgentMode
    agent_name: str = "qwen2.5:3b"
    detail: str
