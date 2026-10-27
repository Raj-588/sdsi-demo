"""Security audit service: structured logging + persistent audit records.

No credentials, secrets, or large payloads are stored — only the decision
metadata needed for governance review.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import Decision, ExecutionStatus, ReasonCode
from app.models.entities import SecurityAuditEvent

logger = logging.getLogger("agentshield.audit")


def record_event(
    db: Session,
    *,
    correlation_id: str,
    task_id: str | None,
    user_id: str | None,
    agent_id: str | None,
    tool: str,
    operation: str,
    resource: str | None,
    decision: Decision,
    reason_code: ReasonCode,
    explanation: str,
    execution_status: ExecutionStatus,
) -> SecurityAuditEvent:
    event = SecurityAuditEvent(
        correlation_id=correlation_id,
        task_id=task_id,
        user_id=user_id,
        agent_id=agent_id,
        tool=tool,
        operation=operation,
        resource=resource,
        decision=decision,
        reason_code=reason_code,
        explanation=explanation,
        execution_status=execution_status,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    logger.info(
        "audit decision=%s reason=%s tool=%s op=%s resource=%s exec=%s corr=%s task=%s",
        decision.value, reason_code.value, tool, operation, resource,
        execution_status.value, correlation_id, task_id,
    )
    return event


def list_events(
    db: Session,
    *,
    decision: Decision | None = None,
    tool: str | None = None,
    limit: int = 100,
) -> list[SecurityAuditEvent]:
    stmt = select(SecurityAuditEvent).order_by(SecurityAuditEvent.timestamp.desc())
    if decision is not None:
        stmt = stmt.where(SecurityAuditEvent.decision == decision)
    if tool is not None:
        stmt = stmt.where(SecurityAuditEvent.tool == tool)
    stmt = stmt.limit(limit)
    return list(db.execute(stmt).scalars().all())
