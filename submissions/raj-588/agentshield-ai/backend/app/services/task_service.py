"""Trusted task authorization service.

Tasks are created by trusted application logic — from predefined templates or
an explicit permission payload supplied by the trusted app. The LLM never
calls this service, and untrusted document text never influences scope.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import TaskStatus
from app.models.entities import AuthorizedTask, TaskPermission
from app.schemas.models import TaskCreate, TaskPermissionIn
from app.services.intentlock import TaskScope

settings = get_settings()


# Predefined trusted task templates (server-owned, not LLM-owned).
TASK_TEMPLATES: dict[str, dict] = {
    "summarize_q3_report": {
        "original_request": "Read the quarterly sales report (Q3) and prepare a summary.",
        "permission": {
            "allowed_tools": ["read_report"],
            "allowed_operations": ["read"],
            "allowed_resources": ["sales_report_Q3"],
            "argument_constraints": {},
            "sensitive_approved": False,
        },
    },
    "summarize_q2_report": {
        "original_request": "Read the quarterly sales report (Q2) and prepare a summary.",
        "permission": {
            "allowed_tools": ["read_report"],
            "allowed_operations": ["read"],
            "allowed_resources": ["sales_report_Q2"],
            "argument_constraints": {},
            "sensitive_approved": False,
        },
    },
    "authorized_record_deletion": {
        "original_request": "Delete a specific obsolete customer record at the user's request.",
        "permission": {
            # Least privilege: delete is permitted, but ONLY for this one record.
            "allowed_tools": ["delete_record"],
            "allowed_operations": ["delete"],
            "allowed_resources": ["CUST-1003"],
            "argument_constraints": {},
            # False -> first evaluation yields REQUIRES_APPROVAL (human in the loop).
            "sensitive_approved": False,
        },
    },
    "approved_customer_export": {
        "original_request": "Perform an approved customer-data export for compliance.",
        "permission": {
            "allowed_tools": ["export_customers"],
            "allowed_operations": ["export"],
            "allowed_resources": [],
            "argument_constraints": {"destination": ["APPROVED_INTERNAL_VAULT"]},
            # Sensitive but NOT pre-approved -> engine returns REQUIRES_APPROVAL.
            "sensitive_approved": False,
        },
    },
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_task(db: Session, payload: TaskCreate, user_id: str) -> AuthorizedTask:
    perm_data: dict
    original_request = payload.original_request

    if payload.template_id:
        template = TASK_TEMPLATES.get(payload.template_id)
        if template is None:
            raise ValueError(f"unknown template_id: {payload.template_id}")
        perm_data = dict(template["permission"])
        original_request = payload.original_request or template["original_request"]
    elif payload.permission is not None:
        perm_data = payload.permission.model_dump()
    else:
        # Default-deny posture: a task with no explicit grant can do nothing.
        perm_data = TaskPermissionIn().model_dump()

    ttl = payload.ttl_minutes or settings.default_task_ttl_minutes
    task = AuthorizedTask(
        user_id=user_id,
        original_request=original_request,
        status=TaskStatus.ACTIVE,
        expires_at=_utcnow() + timedelta(minutes=ttl),
    )
    task.permission = TaskPermission(**perm_data)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def get_task(db: Session, task_id: str) -> AuthorizedTask | None:
    return db.get(AuthorizedTask, task_id)


def resolve_scope(task: AuthorizedTask) -> TaskScope:
    """Translate the persisted task + permission into the pure engine input."""
    p = task.permission
    return TaskScope(
        task_id=task.id,
        owner_user_id=task.user_id,
        status=TaskStatus(task.status),
        expires_at=task.expires_at,
        allowed_tools=list(p.allowed_tools) if p else [],
        allowed_operations=list(p.allowed_operations) if p else [],
        allowed_resources=list(p.allowed_resources) if p else [],
        argument_constraints=dict(p.argument_constraints) if p else {},
        sensitive_approved=bool(p.sensitive_approved) if p else False,
    )
