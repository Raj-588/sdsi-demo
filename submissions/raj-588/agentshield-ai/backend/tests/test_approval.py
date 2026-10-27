"""Approval-workflow tests: a legitimately user-intended delete runs only after
a trusted approval, exactly once, and approval can neither be replayed nor
redirected to a different call."""
from __future__ import annotations

from app.core.enums import Decision, ExecutionStatus
from app.schemas.models import TaskCreate, ToolCall
from app.services import approval_service, gateway_service, task_service

USER = "user-demo-001"


def _delete_task(db):
    return task_service.create_task(
        db, TaskCreate(template_id="authorized_record_deletion", original_request=""),
        user_id=USER,
    )


def _delete_call():
    return ToolCall(tool="delete_record", operation="delete", resource="CUST-1003")


def test_delete_first_requires_approval_and_does_not_execute(db):
    task = _delete_task(db)
    resp = gateway_service.evaluate_and_execute(db, task_id=task.id, call=_delete_call())
    assert resp.decision == Decision.REQUIRES_APPROVAL
    assert resp.execution_status == ExecutionStatus.BLOCKED
    assert resp.result is None
    assert resp.approval_request_id is not None  # a pending approval was created


def test_delete_executes_after_trusted_approval(db):
    task = _delete_task(db)
    first = gateway_service.evaluate_and_execute(db, task_id=task.id, call=_delete_call())
    approval_service.approve(db, first.approval_request_id, approver="trusted-approver")

    second = gateway_service.evaluate_and_execute(db, task_id=task.id, call=_delete_call())
    assert second.decision == Decision.ALLOW
    assert second.execution_status == ExecutionStatus.EXECUTED
    assert second.result is not None and second.result.get("simulated") is True


def test_approval_is_single_use(db):
    task = _delete_task(db)
    first = gateway_service.evaluate_and_execute(db, task_id=task.id, call=_delete_call())
    approval_service.approve(db, first.approval_request_id, approver="trusted-approver")

    ok = gateway_service.evaluate_and_execute(db, task_id=task.id, call=_delete_call())
    assert ok.decision == Decision.ALLOW and ok.execution_status == ExecutionStatus.EXECUTED

    # A second attempt is held again — the approval was consumed.
    replay = gateway_service.evaluate_and_execute(db, task_id=task.id, call=_delete_call())
    assert replay.decision == Decision.REQUIRES_APPROVAL
    assert replay.execution_status == ExecutionStatus.BLOCKED


def test_approval_cannot_be_redirected_to_other_resource(db):
    task = _delete_task(db)  # scoped to CUST-1003 only
    first = gateway_service.evaluate_and_execute(db, task_id=task.id, call=_delete_call())
    approval_service.approve(db, first.approval_request_id, approver="trusted-approver")

    # An injected delete of a DIFFERENT record: not in scope -> DENY, and the
    # existing approval (for CUST-1003) does not apply.
    other = ToolCall(tool="delete_record", operation="delete", resource="CUST-1001")
    resp = gateway_service.evaluate_and_execute(db, task_id=task.id, call=other)
    assert resp.decision == Decision.DENY
    assert resp.execution_status == ExecutionStatus.BLOCKED


def test_approval_endpoints(client):
    task = client.post("/api/v1/tasks", json={
        "template_id": "authorized_record_deletion", "original_request": ""}).json()
    ev = client.post("/api/v1/gateway/evaluate", json={
        "task_id": task["id"],
        "call": {"tool": "delete_record", "operation": "delete", "resource": "CUST-1003"},
    }).json()
    assert ev["decision"] == "REQUIRES_APPROVAL"
    aid = ev["approval_request_id"]

    pending = client.get("/api/v1/approvals?pending_only=true").json()
    assert any(a["id"] == aid for a in pending)

    approved = client.post(f"/api/v1/approvals/{aid}/approve").json()
    assert approved["approved"] is True

    run = client.post("/api/v1/gateway/evaluate", json={
        "task_id": task["id"],
        "call": {"tool": "delete_record", "operation": "delete", "resource": "CUST-1003"},
    }).json()
    assert run["decision"] == "ALLOW"
    assert run["execution_status"] == "EXECUTED"
