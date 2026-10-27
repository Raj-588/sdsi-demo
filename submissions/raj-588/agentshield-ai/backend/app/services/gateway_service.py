"""AgentShield security gateway — the single enforcement chokepoint.

ALL protected tool calls pass through `evaluate_and_execute`. The sandbox
executor is invoked **only** when IntentLock returns ALLOW. DENY and
REQUIRES_APPROVAL never reach execution. Every call produces an audit event.
"""
from __future__ import annotations

import logging
import time
import uuid

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import Decision, ExecutionStatus
from app.schemas.models import GatewayEvaluateResponse, ToolCall
from app.services import approval_service, audit_service, intentlock, task_service
from app.tools import registry

logger = logging.getLogger("agentshield.gateway")
settings = get_settings()


def evaluate_and_execute(
    db: Session,
    *,
    task_id: str,
    call: ToolCall,
    execute: bool = True,
    correlation_id: str | None = None,
    caller_user_id: str | None = None,
) -> GatewayEvaluateResponse:
    correlation_id = correlation_id or str(uuid.uuid4())
    caller_user_id = caller_user_id or settings.demo_user_id

    task = task_service.get_task(db, task_id)
    scope = task_service.resolve_scope(task) if task is not None else None

    # For a sensitive tool, resolve whether a trusted, single-use approval
    # matching THIS exact call already exists. The DB lookup lives here (not in
    # the pure engine); the engine only receives the boolean result.
    spec = registry.get_tool(call.tool)
    matched_approval = None
    approval_granted = False
    if scope is not None and spec is not None and spec.is_sensitive:
        matched_approval = approval_service.find_granted_approval(db, task_id, call)
        approval_granted = matched_approval is not None

    # Deterministic policy evaluation (pure function).
    t0 = time.perf_counter()
    policy = intentlock.evaluate(scope, call, caller_user_id, approval_granted=approval_granted)
    gateway_latency_ms = (time.perf_counter() - t0) * 1000.0
    logger.info("intentlock_latency_ms=%.3f corr=%s", gateway_latency_ms, correlation_id)

    result: dict | None = None
    execution_status = ExecutionStatus.NOT_EXECUTED
    approval_request_id: str | None = None

    if policy.decision == Decision.ALLOW and execute:
        try:
            # Guaranteed non-None: ALLOW implies the tool is registered.
            result = spec.executor(call.resource, call.arguments)  # type: ignore[union-attr]
            execution_status = ExecutionStatus.EXECUTED
            # Single-use: burn the approval so it can't authorize a replay.
            if matched_approval is not None:
                approval_service.consume(db, matched_approval)
        except Exception as exc:  # executor failure is isolated, not fatal
            logger.warning("executor_error tool=%s err=%s", call.tool, exc)
            execution_status = ExecutionStatus.FAILED
            result = {"error": "tool execution failed"}
    elif policy.decision == Decision.ALLOW and not execute:
        execution_status = ExecutionStatus.NOT_EXECUTED
    else:
        # DENY or REQUIRES_APPROVAL: executor is never called.
        execution_status = ExecutionStatus.BLOCKED
        # On REQUIRES_APPROVAL, register a pending approval a trusted approver
        # can act on (idempotent: no duplicate pending rows for the same call).
        if policy.decision == Decision.REQUIRES_APPROVAL and scope is not None:
            pending = approval_service.ensure_pending(db, task_id, call)
            approval_request_id = pending.id

    event = audit_service.record_event(
        db,
        correlation_id=correlation_id,
        task_id=task_id,
        user_id=caller_user_id,
        agent_id=settings.agent_id,
        tool=call.tool,
        operation=call.operation,
        resource=call.resource,
        decision=policy.decision,
        reason_code=policy.reason_code,
        explanation=policy.explanation,
        execution_status=execution_status,
    )

    return GatewayEvaluateResponse(
        decision=policy.decision,
        reason_code=policy.reason_code,
        explanation=policy.explanation,
        execution_status=execution_status,
        result=result,
        correlation_id=correlation_id,
        audit_event_id=event.id,
        approval_request_id=approval_request_id,
    )
