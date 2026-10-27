"""Pure-function tests for the IntentLock policy engine (no DB, no I/O)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.enums import Decision, ReasonCode, TaskStatus
from app.schemas.models import ToolCall
from app.services.intentlock import TaskScope, evaluate

OWNER = "user-demo-001"


def make_scope(**overrides) -> TaskScope:
    base = dict(
        task_id="t1",
        owner_user_id=OWNER,
        status=TaskStatus.ACTIVE,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        allowed_tools=["read_report"],
        allowed_operations=["read"],
        allowed_resources=["sales_report_Q3"],
        argument_constraints={},
        sensitive_approved=False,
    )
    base.update(overrides)
    return TaskScope(**base)


def call(tool="read_report", operation="read", resource="sales_report_Q3", arguments=None):
    return ToolCall(tool=tool, operation=operation, resource=resource, arguments=arguments or {})


# --- Allow path ---
def test_authorized_read_allows():
    d = evaluate(make_scope(), call(), OWNER)
    assert d.decision == Decision.ALLOW
    assert d.reason_code == ReasonCode.AUTHORIZED


# --- Missing / invalid task ---
def test_missing_scope_denies():
    d = evaluate(None, call(), OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.TASK_NOT_FOUND


def test_inactive_task_denies():
    d = evaluate(make_scope(status=TaskStatus.REVOKED), call(), OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.TASK_NOT_ACTIVE


def test_expired_task_denies():
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    d = evaluate(make_scope(expires_at=past), call(), OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.TASK_EXPIRED


def test_naive_expiry_treated_as_utc():
    naive_future = (datetime.now(timezone.utc) + timedelta(minutes=10)).replace(tzinfo=None)
    d = evaluate(make_scope(expires_at=naive_future), call(), OWNER)
    assert d.decision == Decision.ALLOW


# --- Ownership ---
def test_ownership_mismatch_denies():
    d = evaluate(make_scope(), call(), "someone-else")
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.OWNERSHIP_MISMATCH


# --- Unknown tool / operation spoof ---
def test_unknown_tool_denies():
    d = evaluate(make_scope(allowed_tools=["ghost"]), call(tool="ghost"), OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.POLICY_VALIDATION_ERROR


def test_operation_spoof_denies():
    # Declared op doesn't match the tool's real op.
    d = evaluate(make_scope(), call(operation="delete"), OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.OPERATION_NOT_ALLOWED


# --- Allowlist checks ---
def test_tool_not_in_allowlist_denies():
    d = evaluate(
        make_scope(allowed_tools=["query_customer"], allowed_operations=["read"]),
        call(), OWNER,
    )
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.TOOL_NOT_ALLOWED


def test_operation_not_in_allowlist_denies():
    d = evaluate(make_scope(allowed_operations=["export"]), call(), OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.OPERATION_NOT_ALLOWED


def test_cross_resource_denies():
    d = evaluate(make_scope(), call(resource="sales_report_Q2"), OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.RESOURCE_NOT_ALLOWED


def test_missing_required_resource_denies():
    d = evaluate(make_scope(), call(resource=None), OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.RESOURCE_NOT_ALLOWED


# --- Argument schema & constraints ---
def test_unexpected_argument_denies():
    scope = make_scope(
        allowed_tools=["send_notification"], allowed_operations=["notify"],
        allowed_resources=[],
    )
    c = ToolCall(tool="send_notification", operation="notify", resource=None,
                 arguments={"bogus": "x"})
    d = evaluate(scope, c, OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.ARGUMENT_POLICY_VIOLATION


def test_argument_constraint_violation_denies():
    scope = make_scope(
        allowed_tools=["send_notification"], allowed_operations=["notify"],
        allowed_resources=[], argument_constraints={"destination": ["internal"]},
    )
    c = ToolCall(tool="send_notification", operation="notify", resource=None,
                 arguments={"destination": "external"})
    d = evaluate(scope, c, OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.ARGUMENT_POLICY_VIOLATION


def test_argument_constraint_satisfied_allows():
    scope = make_scope(
        allowed_tools=["send_notification"], allowed_operations=["notify"],
        allowed_resources=[], argument_constraints={"destination": ["internal"]},
    )
    c = ToolCall(tool="send_notification", operation="notify", resource=None,
                 arguments={"destination": "internal"})
    d = evaluate(scope, c, OWNER)
    assert d.decision == Decision.ALLOW


# --- Sensitive tools ---
def test_sensitive_tool_without_approval_holds():
    scope = make_scope(
        allowed_tools=["export_customers"], allowed_operations=["export"],
        allowed_resources=[], sensitive_approved=False,
    )
    c = ToolCall(tool="export_customers", operation="export", resource=None, arguments={})
    d = evaluate(scope, c, OWNER)
    assert d.decision == Decision.REQUIRES_APPROVAL
    assert d.reason_code == ReasonCode.APPROVAL_REQUIRED


def test_sensitive_tool_with_approval_allows():
    scope = make_scope(
        allowed_tools=["export_customers"], allowed_operations=["export"],
        allowed_resources=[], sensitive_approved=True,
    )
    c = ToolCall(tool="export_customers", operation="export", resource=None, arguments={})
    d = evaluate(scope, c, OWNER)
    assert d.decision == Decision.ALLOW


def test_delete_not_in_scope_denies_before_approval():
    # delete_record is sensitive, but it is not in the allowlist -> DENY wins.
    scope = make_scope()  # only read_report allowed
    c = ToolCall(tool="delete_record", operation="delete", resource="x", arguments={})
    d = evaluate(scope, c, OWNER)
    assert d.decision == Decision.DENY
    assert d.reason_code == ReasonCode.TOOL_NOT_ALLOWED


@pytest.mark.parametrize("tool", ["export_customers", "delete_record", "send_notification"])
def test_injection_tools_denied_under_read_only_scope(tool):
    """A read-only report task must deny every injected sensitive/destructive tool."""
    ops = {"export_customers": "export", "delete_record": "delete", "send_notification": "notify"}
    c = ToolCall(tool=tool, operation=ops[tool], resource=None, arguments={})
    d = evaluate(make_scope(), c, OWNER)
    assert d.decision == Decision.DENY
