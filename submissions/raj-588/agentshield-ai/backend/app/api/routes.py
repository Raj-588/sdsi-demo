"""REST API routes for AgentShield AI (v1)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import Decision
from app.db.session import get_db
from app.schemas.models import (
    AgentRunRequest,
    AgentRunResponse,
    AuditRecordOut,
    DashboardMetrics,
    GatewayEvaluateRequest,
    GatewayEvaluateResponse,
    LLMStatus,
    TaskCreate,
    TaskOut,
)
from app.schemas.models import ApprovalOut
from app.services import (
    agent_service,
    approval_service,
    audit_service,
    gateway_service,
    task_service,
)
from app.services.scenarios import SCENARIOS

settings = get_settings()
router = APIRouter(prefix="/api/v1")


@router.get("/scenarios")
def list_scenarios() -> list[dict]:
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "expected_decision": s["expected_for_attack_call"].value,
            "attack_tool": s["attack_tool"],
        }
        for s in SCENARIOS
    ]


@router.post("/tasks", response_model=TaskOut, status_code=201)
def create_task(payload: TaskCreate, db: Session = Depends(get_db)) -> TaskOut:
    # Dev-only identity: server binds the fixed synthetic user. In production
    # this must come from an authenticated principal, never the request body.
    try:
        task = task_service.create_task(db, payload, user_id=settings.demo_user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return TaskOut.model_validate(task)


@router.get("/tasks/{task_id}", response_model=TaskOut)
def get_task(task_id: str, db: Session = Depends(get_db)) -> TaskOut:
    task = task_service.get_task(db, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task_not_found")
    return TaskOut.model_validate(task)


@router.post("/gateway/evaluate", response_model=GatewayEvaluateResponse)
def gateway_evaluate(
    payload: GatewayEvaluateRequest, db: Session = Depends(get_db)
) -> GatewayEvaluateResponse:
    # caller_user_id is bound server-side; client cannot assert ownership.
    return gateway_service.evaluate_and_execute(
        db,
        task_id=payload.task_id,
        call=payload.call,
        execute=payload.execute,
        correlation_id=payload.correlation_id,
        caller_user_id=settings.demo_user_id,
    )


@router.post("/agent/run", response_model=AgentRunResponse)
def agent_run(payload: AgentRunRequest, db: Session = Depends(get_db)) -> AgentRunResponse:
    try:
        return agent_service.run_agent(
            db,
            task_id=payload.task_id,
            user_request=payload.user_request,
            document_name=payload.document_name,
            document_content=payload.document_content,
            scenario_id=payload.scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/audit", response_model=list[AuditRecordOut])
def get_audit(
    decision: Decision | None = None,
    tool: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[AuditRecordOut]:
    events = audit_service.list_events(db, decision=decision, tool=tool, limit=limit)
    return [AuditRecordOut.model_validate(e) for e in events]


@router.get("/dashboard/metrics", response_model=DashboardMetrics)
def dashboard_metrics(db: Session = Depends(get_db)) -> DashboardMetrics:
    events = audit_service.list_events(db, limit=500)
    allowed = sum(1 for e in events if e.decision == Decision.ALLOW)
    denied = sum(1 for e in events if e.decision == Decision.DENY)
    approval = sum(1 for e in events if e.decision == Decision.REQUIRES_APPROVAL)
    executed = sum(1 for e in events if str(e.execution_status) == "EXECUTED")
    blocked = sum(1 for e in events if str(e.execution_status) == "BLOCKED")
    recent = [AuditRecordOut.model_validate(e) for e in events[:15]]
    return DashboardMetrics(
        total_proposed=len(events), allowed=allowed, denied=denied,
        requires_approval=approval, executed=executed, blocked=blocked,
        recent_events=recent,
    )


@router.get("/approvals", response_model=list[ApprovalOut])
def list_approvals(
    pending_only: bool = False, db: Session = Depends(get_db)
) -> list[ApprovalOut]:
    reqs = approval_service.list_requests(db, pending_only=pending_only)
    return [ApprovalOut.model_validate(r) for r in reqs]


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalOut)
def approve_request(approval_id: str, db: Session = Depends(get_db)) -> ApprovalOut:
    # DEV-ONLY approver identity. In production this endpoint must require an
    # authenticated human/service principal distinct from the agent, with its
    # own authz — never the same identity that proposed the action.
    req = approval_service.approve(db, approval_id, approver="trusted-approver-dev")
    if req is None:
        raise HTTPException(status_code=404, detail="approval_not_found")
    return ApprovalOut.model_validate(req)


@router.get("/llm/status", response_model=LLMStatus)
def llm_status() -> LLMStatus:
    s = agent_service.llm_status()
    return LLMStatus(
        ollama_available=s["available"],
        provider=s["provider"],
        model=s["model"],
        mode=s["mode"],
        agent_name=s.get("agent_name", "qwen2.5:3b"),
        detail=s["detail"],
    )


@router.post("/demo/seed")
def seed_data() -> dict:
    from app.db.seed_demo_data import seed_demo_data
    return seed_demo_data(clear_existing=True)
