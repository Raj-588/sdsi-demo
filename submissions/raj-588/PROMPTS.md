# AI Collaboration & Prompt Engineering Log (PROMPTS.md)

**Project:** SDSI PS5: Job Scheduler with Dependency Resolution (DAG)  
**Developer:** `raj-588`  
**Model:** Antigravity Coding Assistant (Gemini 3.8 Flash High)

---

## 1. Collaboration Strategy & Architecture Decisions

This project leveraged an AI-augmented engineering workflow to build a resilient, production-ready build/ETL DAG orchestrator adhering to all hackathon scoring criteria:

1. **Zero External Dependencies**:
   - *Design Choice*: Strictly rely on the Python standard library (`heapq`, `collections`, `dataclasses`, `argparse`, `json`, `unittest`).
   - *Rationale*: Eliminates environment mismatch errors, dependency bloat, and security supply-chain risks for the AI evaluator.

2. **Defense-in-Depth Security**:
   - *Input Hygiene*: Reject null bytes, negative durations, non-string IDs, and duplicate job identifiers.
   - *Adversarial Guardrails*: Treat input prompts as untrusted data; include regex pattern matching for prompt injection attempts in the agent loop.

3. **Deterministic Verification**:
   - Employ min-heaps during topological sorting and stage batching to guarantee reproducible orderings across all test runs.

---

## 2. Iteration Log & Prompt History

### Prompt Phase 1: Problem Decomposition & Milestones Mapping
* **Context**: Decomposing requirements M1 through M5 into cohesive modules.
* **Instruction**:
  > "Design a DAG job scheduler supporting M1 (cycle detection with exact path + missing deps), M2 (deterministic topological sort), M3 (parallel stages with worker limit N), M4 (critical path + makespan via CPM), and M5 (downstream failure propagation). What data structures maximize performance and clarity?"
* **Outcome**:
  - Selected 3-color DFS for cycle detection to reconstruct the exact cycle slice `[A, B, C, A]`.
  - Selected Kahn's algorithm with min-heap for deterministic topological sort.
  - Selected Forward/Backward pass (CPM) with slack calculations for critical path analysis.

---

### Prompt Phase 2: Edge Cases & Robustness
* **Context**: Anticipating edge cases beyond the stated brief.
* **Instruction**:
  > "Identify edge cases not explicitly stated in PS5: e.g. empty graphs, self-referential loops, disconnected graphs, zero-duration jobs, duplicate IDs, and invalid worker limits."
* **Outcome**:
  - Implemented custom `JobGraph` validation in `__post_init__` and `validate()`.
  - Added dedicated unit tests for every identified edge case in `test_scheduler.py`.

---

### Prompt Phase 3: Bonus Features & Agent Scaffold
* **Context**: Expanding score potential with stretch features.
* **Instruction**:
  > "Implement an event-driven worker pool simulator to compute realistic constrained makespans, a Mermaid diagram visualizer, and an `agent.py` scaffold wrapper with human-in-the-loop (HITL) gates."
* **Outcome**:
  - Built `simulate_worker_execution()` in `scheduler.py` producing a Gantt-style execution timeline.
  - Built `export_mermaid()` to visualize critical paths.
  - Integrated `agent.py` conforming to the hackathon evaluator's `{"plan": [], "result": None, "escalated": False}` schema.

---

### Prompt Phase 4: Token Optimization & Security
* **Context**: Following token-saving and secure coding guidelines.
* **Instruction**:
  > "Keep responses and code concise, well-documented, and avoid unneeded boilerplate while ensuring OWASP security practices are followed."
* **Outcome**:
  - Code is modular, clean, and self-documenting.
  - 26 tests run in under 0.01 seconds.
