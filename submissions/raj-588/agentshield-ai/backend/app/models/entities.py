"""ORM models: Users, AuthorizedTasks, TaskPermissions, ToolDefinitions,
AgentExecutions, SecurityAuditEvents, ApprovalRequests.

Design notes
------------
* Permissions are stored as JSON lists on the task permission row for MVP
  simplicity; this maps cleanly to a child table later if needed.
* All timestamps are timezone-aware UTC.
* Indexes are declared on the columns the gateway and dashboard filter on.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    Decision,
    ExecutionStatus,
    ReasonCode,
    TaskStatus,
)
from app.db.session import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    tasks: Mapped[list["AuthorizedTask"]] = relationship(back_populates="user")


class ToolDefinition(Base):
    __tablename__ = "tool_definitions"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    # JSON schema (dict) describing the accepted arguments.
    arg_schema: Mapped[dict] = mapped_column(JSON, default=dict)


class AuthorizedTask(Base):
    __tablename__ = "authorized_tasks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    original_request: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[TaskStatus] = mapped_column(String(16), default=TaskStatus.ACTIVE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship(back_populates="tasks")
    permission: Mapped["TaskPermission"] = relationship(
        back_populates="task", uselist=False, cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_tasks_user_status", "user_id", "status"),)


class TaskPermission(Base):
    """The trusted, server-side scope. This is the authority IntentLock trusts.

    It is created by trusted application logic from task templates — never by
    the LLM and never derived from untrusted document text.
    """

    __tablename__ = "task_permissions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(
        ForeignKey("authorized_tasks.id"), nullable=False, unique=True
    )
    allowed_tools: Mapped[list] = mapped_column(JSON, default=list)
    allowed_operations: Mapped[list] = mapped_column(JSON, default=list)
    allowed_resources: Mapped[list] = mapped_column(JSON, default=list)
    # Optional per-argument constraints, e.g. {"destination": ["internal"]}.
    argument_constraints: Mapped[dict] = mapped_column(JSON, default=dict)
    # Sensitive tools listed here are permitted only after approval.
    sensitive_approved: Mapped[bool] = mapped_column(Boolean, default=False)

    task: Mapped["AuthorizedTask"] = relationship(back_populates="permission")


class AgentExecution(Base):
    __tablename__ = "agent_executions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("authorized_tasks.id"), nullable=False)
    agent_mode: Mapped[str] = mapped_column(String(8), nullable=False)
    user_request: Mapped[str] = mapped_column(Text, nullable=False)
    document_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    proposed_calls: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SecurityAuditEvent(Base):
    __tablename__ = "security_audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    task_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision: Mapped[Decision] = mapped_column(String(24), index=True, nullable=False)
    reason_code: Mapped[ReasonCode] = mapped_column(String(32), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    execution_status: Mapped[ExecutionStatus] = mapped_column(String(16), nullable=False)

    __table_args__ = (Index("ix_audit_decision_ts", "decision", "timestamp"),)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    task_id: Mapped[str] = mapped_column(ForeignKey("authorized_tasks.id"), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(128), nullable=True)
    arguments: Mapped[dict] = mapped_column(JSON, default=dict)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    # Single-use: an approval authorizes exactly one execution (replay-safe).
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
