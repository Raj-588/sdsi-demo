"""Trusted approval workflow for sensitive actions (e.g. a legitimate delete).

An approval is bound to a *specific* (task, tool, resource, arguments) tuple, is
granted by a trusted approver (a principal separate from the LLM), and is
single-use. This is what lets a genuinely user-intended destructive action run
while an injected one with different arguments or resource cannot reuse it.

The LLM and document text never touch this module. In production the approver
must be an authenticated human/service distinct from the agent; here it is a
dev-only endpoint, clearly labelled.
"""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import ApprovalRequest
from app.schemas.models import ToolCall


def _args_key(arguments: dict) -> str:
    return json.dumps(arguments or {}, sort_keys=True)


def _matches(req: ApprovalRequest, task_id: str, call: ToolCall) -> bool:
    return (
        req.task_id == task_id
        and req.tool == call.tool
        and (req.resource or None) == (call.resource or None)
        and _args_key(req.arguments) == _args_key(call.arguments)
    )


def find_granted_approval(
    db: Session, task_id: str, call: ToolCall
) -> ApprovalRequest | None:
    """Return an approved, not-yet-consumed approval matching this exact call."""
    stmt = select(ApprovalRequest).where(
        ApprovalRequest.task_id == task_id,
        ApprovalRequest.tool == call.tool,
        ApprovalRequest.approved.is_(True),
        ApprovalRequest.consumed.is_(False),
    )
    for req in db.execute(stmt).scalars().all():
        if _matches(req, task_id, call):
            return req
    return None


def ensure_pending(db: Session, task_id: str, call: ToolCall) -> ApprovalRequest:
    """Get-or-create a pending approval for this exact call (no duplicates)."""
    stmt = select(ApprovalRequest).where(
        ApprovalRequest.task_id == task_id,
        ApprovalRequest.tool == call.tool,
        ApprovalRequest.approved.is_(False),
    )
    for req in db.execute(stmt).scalars().all():
        if _matches(req, task_id, call):
            return req
    req = ApprovalRequest(
        task_id=task_id, tool=call.tool, resource=call.resource,
        arguments=dict(call.arguments or {}),
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    return req


def approve(db: Session, approval_id: str, approver: str) -> ApprovalRequest | None:
    from datetime import datetime, timezone

    req = db.get(ApprovalRequest, approval_id)
    if req is None:
        return None
    req.approved = True
    req.approved_by = approver
    req.resolved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(req)
    return req


def consume(db: Session, req: ApprovalRequest) -> None:
    """Mark an approval used so it cannot authorize a second execution."""
    req.consumed = True
    db.commit()


def list_requests(db: Session, *, pending_only: bool = False) -> list[ApprovalRequest]:
    stmt = select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc())
    if pending_only:
        stmt = stmt.where(ApprovalRequest.approved.is_(False))
    return list(db.execute(stmt).scalars().all())
