# API Specification (v1)

Base URL: `http://localhost:8000`. Interactive OpenAPI at `/docs`.

All request bodies are validated by Pydantic v2 with `extra="forbid"` on
security-sensitive models (unknown fields → HTTP 422). A body-size limit
(`MAX_REQUEST_BYTES`, default 256 KB) returns HTTP 413.

## GET /health
200 → `{"status":"ok","app":...,"version":...,"demo_mode":true}`

## GET /api/v1/scenarios
200 → list of `{id, name, expected_decision, attack_tool}`.

## POST /api/v1/tasks
Create a trusted task. The server binds the fixed synthetic user id; any
client identity claim is ignored (dev-only identity).
Request: `{"template_id":"summarize_q3_report","original_request":"","ttl_minutes":60}`
or `{"original_request":"...","permission":{allowed_tools,allowed_operations,allowed_resources,argument_constraints,sensitive_approved}}`.
201 → `TaskOut`. 400 → unknown `template_id`. 422 → validation error.

## GET /api/v1/tasks/{task_id}
200 → `TaskOut`. 404 → `task_not_found`.

## POST /api/v1/gateway/evaluate
Evaluate (and optionally execute) a single proposed tool call.
Request: `{"task_id":"...","call":{"tool","operation","resource","arguments"},"execute":true}`
200 → `{decision, reason_code, explanation, execution_status, result, correlation_id, audit_event_id}`.
`result` is populated only when `decision==ALLOW` and `execute==true`.

## POST /api/v1/agent/run
Run the agent for a task against a document; every proposed call is routed
through the gateway under one correlation id.
Request: `{"task_id","user_request","document_name","document_content","scenario_id"}`
200 → `{task_id, agent_mode, user_response, proposed_calls[], evaluated_calls[], correlation_id}`.
404 → task not found.

## GET /api/v1/audit?decision=&tool=&limit=
200 → list of audit records (most recent first).

## GET /api/v1/dashboard/metrics
200 → `{total_proposed, allowed, denied, requires_approval, executed, blocked, recent_events[]}`.

## GET /api/v1/approvals?pending_only=
200 -> list of approval requests (sensitive actions awaiting a trusted decision).

## POST /api/v1/approvals/{approval_id}/approve
Grant a single-use approval for the exact (task, tool, resource, arguments) it
was raised for. DEV-ONLY approver identity; in production this must require an
authenticated approver distinct from the agent. 200 -> ApprovalOut. 404 -> not found.

## GET /api/v1/llm/status
200 → `{ollama_available, model, mode (LIVE|MOCK), detail}`.

### Reason codes
AUTHORIZED, TASK_NOT_FOUND, TASK_EXPIRED, TASK_NOT_ACTIVE, OWNERSHIP_MISMATCH,
TOOL_NOT_ALLOWED, OPERATION_NOT_ALLOWED, RESOURCE_NOT_ALLOWED,
ARGUMENT_POLICY_VIOLATION, APPROVAL_REQUIRED, POLICY_VALIDATION_ERROR.

### Security note
Endpoints that execute protected actions never accept a caller-supplied
authorization claim as authoritative. Ownership and scope are resolved
server-side from stored task records. Before production: replace the dev
identity with authenticated principals (OIDC/JWT), add authz on task creation,
and rate-limit the agent/gateway endpoints.
