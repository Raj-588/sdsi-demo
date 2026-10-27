# Security Design

## Principle
Authorization is **task-bound** and **independent of the LLM**. The model
proposes; a deterministic, default-deny engine decides. This holds even if the
model is fully subverted by prompt injection, because the decision never depends
on the model recognizing the attack.

## Implemented controls (this MVP)
1. Default-deny: anything not explicitly granted is denied.
2. No direct LLM access to tools, DB, credentials, or execution interfaces.
3. Server-side trusted task scopes, created from templates / trusted app logic.
4. Single gateway chokepoint; executor runs only on ALLOW.
5. Strong tool-argument validation (typed schema, `extra` forbidden).
6. Explicit resource-level allowlists; cross-resource access denied.
7. Operation-spoof check (declared op must match the tool's real op).
8. Sensitive tools are approval-gated; approval never widens scope.
9. No arbitrary code/SQL/shell; no outbound network; sandbox simulations only.
10. Full audit log of every decision (no secrets/credentials stored).
11. Request-size limit and LLM timeout; graceful Ollama-failure fallback.
12. Untrusted document text and tool responses handled as data, not instructions.
13. Unit + regression tests prove denied actions never execute.
14. The LLM cannot create, modify, expand, or approve authorization grants.

## Explicitly NOT claimed
- Not production-certified; not "completely resistant to prompt injection".
- Keyword-based injection detection is **not** used as a security boundary — the
  structural authorization gateway is the boundary.

## Required before production
- Replace dev identity with authenticated principals (OIDC/JWT/mTLS) and authz
  on task creation and approval.
- Move the approval workflow to a separate trusted service with its own authn.
- PostgreSQL with migrations; tamper-evident / append-only audit storage.
- Rate limiting, request signing between agent and gateway, secret management
  (vault), network egress controls on executors.
- Load testing before any throughput/latency claims.
- Formal threat model and red-team review of each tool's argument surface.

## Threats addressed vs. residual
Addressed: injected tool calls outside scope, cross-resource reads, destructive
ops by default, unauthorized exfiltration/notification, expired/forged tasks.
Residual: attacks fully *within* an over-broad granted scope (mitigate with
least-privilege templates), social-engineering of the approval workflow,
supply-chain/model-poisoning, and anything outside the gateway's mediation.

## Handling a legitimate sensitive action (e.g. a user-intended delete)
Destructive or exporting actions are default-deny, but a genuinely user-wanted
one is handled by two layers, both independent of the LLM:

1. **Policy (scope):** a trusted task template grants the tool/operation on a
   *specific* resource with least privilege (e.g. `delete_record` on `CUST-1003`
   only). Anything outside that is denied before approval is ever considered.
2. **Approval (human-in-the-loop):** because the tool is sensitive, IntentLock
   returns `REQUIRES_APPROVAL` and the gateway raises a pending approval bound to
   that exact (task, tool, resource, arguments). A **trusted approver** — a
   principal separate from the agent — approves it. Re-evaluation then returns
   `ALLOW` and the executor runs **once**.

Guarantees: approval is **single-use** (no replay), **call-specific** (an
approval for `CUST-1003` cannot authorize a delete of `CUST-1001`), and **never
widens scope** (it only confirms a call that already passed every allowlist
check). The LLM and document text cannot create or grant approvals. A
prompt-injected delete therefore fails at the policy layer regardless of any
standing approval.

Flow: `POST /gateway/evaluate` (-> REQUIRES_APPROVAL + approval_request_id) ->
`POST /approvals/{id}/approve` (trusted approver) -> `POST /gateway/evaluate`
again (-> ALLOW, EXECUTED). Production: the approve endpoint must be gated to an
authenticated human/service distinct from the agent, ideally with 2-person rules
for destructive operations.
