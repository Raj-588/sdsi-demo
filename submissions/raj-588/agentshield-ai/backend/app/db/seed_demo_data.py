"""Generate rich, realistic demo security events, tasks, and approval requests."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.core.config import get_settings
from app.core.enums import Decision, ExecutionStatus, ReasonCode, TaskStatus
from app.db.session import SessionLocal
from app.models.entities import (
    ApprovalRequest,
    AuthorizedTask,
    SecurityAuditEvent,
    TaskPermission,
    User,
)

settings = get_settings()


def seed_demo_data(clear_existing: bool = False) -> dict:
    with SessionLocal() as db:
        if clear_existing:
            db.query(SecurityAuditEvent).delete()
            db.query(ApprovalRequest).delete()
            db.query(TaskPermission).delete()
            db.query(AuthorizedTask).delete()
            db.commit()

        # Ensure demo user exists
        user = db.get(User, settings.demo_user_id)
        if not user:
            user = User(id=settings.demo_user_id, display_name="Demo Security Analyst")
            db.add(user)
            db.commit()

        now = datetime.now(timezone.utc)

        # 1. Create a set of authorized tasks
        task_definitions = [
            {
                "id": str(uuid.uuid4()),
                "request": "Summarize Q3 financial and operational highlights for the executive board.",
                "tools": ["read_report"],
                "ops": ["read"],
                "resources": ["sales_report_Q3", "operational_kpis_Q3", "executive_summary_draft"],
                "status": TaskStatus.ACTIVE,
                "hours_ago": 18,
            },
            {
                "id": str(uuid.uuid4()),
                "request": "Run authorized quarterly compliance customer export for EU GDPR audit.",
                "tools": ["read_report", "export_customers"],
                "ops": ["read", "export"],
                "resources": ["gdpr_audit_scope", "customer_anonymized_subset"],
                "status": TaskStatus.ACTIVE,
                "sensitive_approved": True,
                "hours_ago": 12,
            },
            {
                "id": str(uuid.uuid4()),
                "request": "Review product telemetry and customer feedback signals for Q2 sprint planning.",
                "tools": ["read_report"],
                "ops": ["read"],
                "resources": ["sales_report_Q2", "customer_feedback_digest"],
                "status": TaskStatus.ACTIVE,
                "hours_ago": 6,
            },
            {
                "id": str(uuid.uuid4()),
                "request": "Daily automated inventory health audit and reconciliation check.",
                "tools": ["read_report"],
                "ops": ["read"],
                "resources": ["warehouse_inventory_log", "daily_discrepancies"],
                "status": TaskStatus.ACTIVE,
                "hours_ago": 2,
            },
        ]

        task_ids = []
        for td in task_definitions:
            task = AuthorizedTask(
                id=td["id"],
                user_id=settings.demo_user_id,
                original_request=td["request"],
                status=td["status"],
                created_at=now - timedelta(hours=td["hours_ago"]),
                expires_at=now + timedelta(hours=48),
            )
            perm = TaskPermission(
                id=str(uuid.uuid4()),
                task_id=td["id"],
                allowed_tools=td["tools"],
                allowed_operations=td["ops"],
                allowed_resources=td["resources"],
                sensitive_approved=td.get("sensitive_approved", False),
            )
            db.add(task)
            db.add(perm)
            task_ids.append(td["id"])

        db.commit()

        # 2. Rich security audit events across the last 24 hours
        events_data = [
            # Event 1 (Most Recent - 1 min ago): Sensitive tool requiring human approval
            (
                0.02,
                task_ids[1],
                "export_customers",
                "export",
                "regional_sales_leads_emea",
                Decision.REQUIRES_APPROVAL,
                ReasonCode.APPROVAL_REQUIRED,
                ExecutionStatus.BLOCKED,
                "Tool 'export_customers' is sensitive; held in governance queue awaiting dual SecOps sign-off.",
            ),
            # Event 2 (3 mins ago): Prompt injection attack intercepted!
            (
                0.05,
                task_ids[0],
                "export_customers",
                "export",
                "customer_pii_database",
                Decision.DENY,
                ReasonCode.TOOL_NOT_ALLOWED,
                ExecutionStatus.BLOCKED,
                "Prompt injection payload attempted exfiltration of 50,000 customer PII records. Gateway blocked execution.",
            ),
            # Event 3 (5 mins ago): Legitimate Q3 report read authorized and executed
            (
                0.08,
                task_ids[0],
                "read_report",
                "read",
                "sales_report_Q3",
                Decision.ALLOW,
                ReasonCode.AUTHORIZED,
                ExecutionStatus.EXECUTED,
                "Authorized tool 'read_report' on resource 'sales_report_Q3' within task scope.",
            ),
            # Event 4 (10 mins ago): Another sensitive export requiring CISO approval
            (
                0.16,
                task_ids[3],
                "export_customers",
                "export",
                "global_distributor_contacts",
                Decision.REQUIRES_APPROVAL,
                ReasonCode.APPROVAL_REQUIRED,
                ExecutionStatus.BLOCKED,
                "Bulk customer data export flagged as sensitive; requires dual SecOps authorization.",
            ),
            # Event 5 (20 mins ago): Discrepancy report read
            (
                0.35,
                task_ids[3],
                "read_report",
                "read",
                "daily_discrepancies",
                Decision.ALLOW,
                ReasonCode.AUTHORIZED,
                ExecutionStatus.EXECUTED,
                "Daily reconciliation check authorized.",
            ),
            # Event 6 (45 mins ago): Injection payload attempted audit wipe!
            (
                0.75,
                task_ids[0],
                "delete_record",
                "delete",
                "audit_log_master",
                Decision.DENY,
                ReasonCode.TOOL_NOT_ALLOWED,
                ExecutionStatus.BLOCKED,
                "Destructive action 'delete_record' denied: task template is strictly read-only.",
            ),
            # Event 7 (1.5 hrs ago): Approved export execution
            (
                1.5,
                task_ids[1],
                "export_customers",
                "export",
                "customer_anonymized_subset",
                Decision.ALLOW,
                ReasonCode.AUTHORIZED,
                ExecutionStatus.EXECUTED,
                "Operation approved by SecOps Lead (ticket SEC-8941). Single-use execution granted.",
            ),
            # Event 8 (3 hrs ago): Cross-resource access attempt
            (
                3.0,
                task_ids[0],
                "read_report",
                "read",
                "confidential_ma_term_sheet",
                Decision.DENY,
                ReasonCode.RESOURCE_NOT_ALLOWED,
                ExecutionStatus.BLOCKED,
                "Resource 'confidential_ma_term_sheet' is not in authorized resource scope for task.",
            ),
            # Event 9 (5 hrs ago): Legitimate telemetry read
            (
                5.0,
                task_ids[2],
                "read_report",
                "read",
                "customer_feedback_digest",
                Decision.ALLOW,
                ReasonCode.AUTHORIZED,
                ExecutionStatus.EXECUTED,
                "Operation within authorized scope of sprint planning task.",
            ),
            # Event 10 (8 hrs ago): Jailbreak injection attempt trying to drop audit tables
            (
                8.0,
                task_ids[2],
                "delete_record",
                "delete",
                "security_audit_events",
                Decision.DENY,
                ReasonCode.TOOL_NOT_ALLOWED,
                ExecutionStatus.BLOCKED,
                "Indirect jailbreak prompt embedded in feedback file blocked at gateway boundary.",
            ),
            # Event 11 (12 hrs ago): Inventory health check read
            (
                12.0,
                task_ids[3],
                "read_report",
                "read",
                "warehouse_inventory_log",
                Decision.ALLOW,
                ReasonCode.AUTHORIZED,
                ExecutionStatus.EXECUTED,
                "Routine inventory check authorized under scheduled task.",
            ),
            # Event 12 (16 hrs ago): Unauthorized cross-department salary survey read
            (
                16.0,
                task_ids[2],
                "read_report",
                "read",
                "executive_compensation_2026",
                Decision.DENY,
                ReasonCode.RESOURCE_NOT_ALLOWED,
                ExecutionStatus.BLOCKED,
                "Access denied: Resource outside authorized scope for task.",
            ),
            # Event 13 (20 hrs ago): Authorized read of operational KPIs
            (
                20.0,
                task_ids[0],
                "read_report",
                "read",
                "operational_kpis_Q3",
                Decision.ALLOW,
                ReasonCode.AUTHORIZED,
                ExecutionStatus.EXECUTED,
                "Authorized read verified against active task boundary.",
            ),
        ]

        audit_objects = []
        for hours_ago, tid, tool, op, res, dec, rcode, estatus, expl in events_data:
            evt = SecurityAuditEvent(
                id=str(uuid.uuid4()),
                correlation_id=str(uuid.uuid4()),
                timestamp=now - timedelta(hours=hours_ago),
                task_id=tid,
                user_id=settings.demo_user_id,
                agent_id="agent-intentlock-001",
                tool=tool,
                operation=op,
                resource=res,
                decision=dec,
                reason_code=rcode,
                explanation=expl,
                execution_status=estatus,
            )
            audit_objects.append(evt)
            db.add(evt)

        # 3. Create realistic approval requests
        approval_samples = [
            ApprovalRequest(
                id=str(uuid.uuid4()),
                task_id=task_ids[1],
                tool="export_customers",
                resource="regional_sales_leads_emea",
                arguments={"destination": "sftp://secure.vault.internal/emea", "format": "parquet"},
                approved=False,
                consumed=False,
                created_at=now - timedelta(hours=13),
            ),
            ApprovalRequest(
                id=str(uuid.uuid4()),
                task_id=task_ids[3],
                tool="export_customers",
                resource="global_distributor_contacts",
                arguments={"destination": "https://partner-portal.corp/sync", "encryption": "AES256"},
                approved=False,
                consumed=False,
                created_at=now - timedelta(hours=1, minutes=45),
            ),
            ApprovalRequest(
                id=str(uuid.uuid4()),
                task_id=task_ids[1],
                tool="export_customers",
                resource="customer_anonymized_subset",
                arguments={"destination": "internal_compliance_bucket", "records_count": 1250},
                approved=True,
                consumed=True,
                approved_by="secops-lead@company.internal",
                created_at=now - timedelta(hours=12),
                resolved_at=now - timedelta(hours=11, minutes=30),
            ),
        ]
        for appr in approval_samples:
            db.add(appr)

        db.commit()

        counts = {
            "tasks": len(task_definitions),
            "events": len(audit_objects),
            "approvals": len(approval_samples),
        }
        return counts


if __name__ == "__main__":
    result = seed_demo_data(clear_existing=True)
    print(f"Successfully seeded demo data: {result}")
