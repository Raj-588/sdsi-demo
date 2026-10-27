"""IntentLock — deterministic, default-deny, task-bound authorization engine.

`evaluate` is a PURE function: no DB access, no I/O, no randomness. It takes an
already-resolved trusted task scope plus a proposed tool call and returns a
typed decision. This purity is what makes the gateway auditable and testable,
and it is the security boundary that holds *even when the LLM is fully fooled
by an injected instruction*.

Evaluation order (first failing check wins; otherwise ALLOW):
  1. task present & scope present      -> TASK_NOT_FOUND / POLICY_VALIDATION_ERROR
  2. task status ACTIVE                -> TASK_NOT_ACTIVE
  3. task not expired                  -> TASK_EXPIRED
  4. caller owns task                  -> OWNERSHIP_MISMATCH
  5. tool known to registry            -> POLICY_VALIDATION_ERROR
  6. declared operation matches tool   -> OPERATION_NOT_ALLOWED
  7. tool in task allowlist            -> TOOL_NOT_ALLOWED
  8. operation in task allowlist       -> OPERATION_NOT_ALLOWED
  9. resource in task allowlist        -> RESOURCE_NOT_ALLOWED
 10. argument schema + constraints     -> ARGUMENT_POLICY_VIOLATION
 11. sensitive tool handling           -> APPROVAL_REQUIRED / DENY
 12. otherwise                         -> ALLOW
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.core.enums import Decision, ReasonCode, TaskStatus
from app.schemas.models import PolicyDecision, ToolCall
from app.tools import registry


@dataclass(frozen=True)
class TaskScope:
    """The trusted, server-resolved authorization scope handed to IntentLock."""

    task_id: str
    owner_user_id: str
    status: TaskStatus
    expires_at: datetime
    allowed_tools: list[str]
    allowed_operations: list[str]
    allowed_resources: list[str]
    argument_constraints: dict
    sensitive_approved: bool


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _decision(decision: Decision, reason: ReasonCode, explanation: str) -> PolicyDecision:
    return PolicyDecision(decision=decision, reason_code=reason, explanation=explanation)


def evaluate(
    scope: TaskScope | None,
    call: ToolCall,
    caller_user_id: str,
    approval_granted: bool = False,
) -> PolicyDecision:
    # 1. Task + scope presence
    if scope is None:
        return _decision(
            Decision.DENY, ReasonCode.TASK_NOT_FOUND,
            "No trusted task scope could be resolved for this call.",
        )

    # 2. Status
    if scope.status != TaskStatus.ACTIVE:
        return _decision(
            Decision.DENY, ReasonCode.TASK_NOT_ACTIVE,
            f"Task status is {scope.status.value}; only ACTIVE tasks may act.",
        )

    # 3. Expiry
    expires = scope.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= _now():
        return _decision(
            Decision.DENY, ReasonCode.TASK_EXPIRED,
            "Task authorization window has expired.",
        )

    # 4. Ownership — client-asserted identity is never authoritative; the
    #    gateway passes the server-bound caller id, which must match the owner.
    if caller_user_id != scope.owner_user_id:
        return _decision(
            Decision.DENY, ReasonCode.OWNERSHIP_MISMATCH,
            "Caller does not own this task.",
        )

    # 5. Tool must exist in the trusted registry
    spec = registry.get_tool(call.tool)
    if spec is None:
        return _decision(
            Decision.DENY, ReasonCode.POLICY_VALIDATION_ERROR,
            f"Tool '{call.tool}' is not a registered capability.",
        )

    # 6. Declared operation must match the tool's true operation (anti-spoof)
    if call.operation != spec.operation:
        return _decision(
            Decision.DENY, ReasonCode.OPERATION_NOT_ALLOWED,
            f"Declared operation '{call.operation}' does not match tool "
            f"'{spec.name}' operation '{spec.operation}'.",
        )

    # 7. Tool allowlist
    if spec.name not in scope.allowed_tools:
        return _decision(
            Decision.DENY, ReasonCode.TOOL_NOT_ALLOWED,
            f"Tool '{spec.name}' is not in the task's allowed tools.",
        )

    # 8. Operation allowlist
    if spec.operation not in scope.allowed_operations:
        return _decision(
            Decision.DENY, ReasonCode.OPERATION_NOT_ALLOWED,
            f"Operation '{spec.operation}' is not in the task's allowed operations.",
        )

    # 9. Resource allowlist (tools that act on a resource must name an allowed one)
    resource_required = spec.name in {"read_report", "query_customer", "delete_record"}
    if resource_required or call.resource is not None:
        if call.resource is None:
            return _decision(
                Decision.DENY, ReasonCode.RESOURCE_NOT_ALLOWED,
                f"Tool '{spec.name}' requires a resource, none was provided.",
            )
        if call.resource not in scope.allowed_resources:
            return _decision(
                Decision.DENY, ReasonCode.RESOURCE_NOT_ALLOWED,
                f"Resource '{call.resource}' is not in the task's allowed resources.",
            )

    # 10. Argument schema + per-task constraints
    arg_error = registry.validate_arguments(spec, call.arguments)
    if arg_error is not None:
        return _decision(
            Decision.DENY, ReasonCode.ARGUMENT_POLICY_VIOLATION,
            f"Argument validation failed: {arg_error}.",
        )
    constraint_error = _check_constraints(scope.argument_constraints, call.arguments)
    if constraint_error is not None:
        return _decision(
            Decision.DENY, ReasonCode.ARGUMENT_POLICY_VIOLATION,
            f"Argument constraint violated: {constraint_error}.",
        )

    # 11. Sensitive-tool handling.
    #   A sensitive tool needs an approval signal to proceed. That signal is
    #   either a standing template grant (scope.sensitive_approved) or a
    #   per-call human approval resolved by the gateway (approval_granted).
    #   Crucially, we only reach this point AFTER every allowlist/resource/
    #   argument check has passed — so approval can authorize a call that is
    #   already in scope, but it can NEVER widen scope.
    if spec.is_sensitive and not scope.sensitive_approved and not approval_granted:
        return _decision(
            Decision.REQUIRES_APPROVAL, ReasonCode.APPROVAL_REQUIRED,
            f"Tool '{spec.name}' is sensitive and requires explicit human "
            "approval; execution is held pending a trusted approval.",
        )

    # 12. Allow
    return _decision(
        Decision.ALLOW, ReasonCode.AUTHORIZED,
        f"Call to '{spec.name}' on '{call.resource}' is within trusted task scope.",
    )


def _check_constraints(constraints: dict, arguments: dict) -> str | None:
    """Each constraint maps an arg name to a list of permitted values."""
    for arg, allowed_values in constraints.items():
        if arg in arguments and arguments[arg] not in allowed_values:
            return f"{arg}='{arguments[arg]}' not in permitted set {allowed_values}"
    return None
