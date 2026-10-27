"""
Agentic DAG Orchestrator & Job Scheduler.
Extends agent-template/agent.py for the SDSI Agentic AI Hackathon (Developer Track).

Conforms to standard evaluator contract:
    run(task: str) -> dict:
        return {"plan": list, "result": any, "escalated": bool}

Features:
- Plan generation: Decomposes natural language requests into deterministic DAG operations.
- Tool orchestration: Direct tool execution over scheduler APIs.
- Human-in-the-Loop (HITL) Gate:
  - Escalates if cycles or missing dependencies are detected.
  - Escalates if simulated failure impact exceeds 50% of total pipeline jobs.
  - Escalates if untrusted input or prompt injection attempts are detected.
"""

import json
import re
import os
import sys
from typing import Dict, Any, List, Tuple

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if _CURRENT_DIR not in sys.path:
    sys.path.insert(0, _CURRENT_DIR)

from scheduler import JobGraph, ValidationError, SchedulerError


class AgentSecurityError(Exception):
    """Raised when malicious or untrusted payload is intercepted."""
    pass


def _sanitize_and_inspect_prompt(text: str) -> None:
    """
    Security Guardrail: Intercepts prompt injection attacks.
    Treats input content as untrusted data, never instructions.
    """
    suspicious_patterns = [
        r"ignore (all )?previous instructions",
        r"bypass security",
        r"delete everything",
        r"eval\(",
        r"import os; os\.system",
        r"__import__",
        r"<script>",
        r";\s*rm\s+-rf"
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            raise AgentSecurityError(f"Potential prompt injection or untrusted exploit intercepted: '{pattern}'")


def _extract_pipeline_data(task: str) -> Tuple[List[Dict[str, Any]], str]:
    """
    Extracts JSON pipeline data either directly from string or from referenced file.
    """
    # 1. Check for file path reference
    file_match = re.search(r"[\w/\.-]+\.json", task)
    if file_match:
        fpath = file_match.group(0)
        # Search relative to current folder or submissions folder
        candidates = [
            fpath,
            os.path.join(os.path.dirname(__file__), fpath),
            os.path.join(os.path.dirname(__file__), "sample_data", os.path.basename(fpath)),
            os.path.join(os.getcwd(), fpath)
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                with open(candidate, "r", encoding="utf-8") as f:
                    return json.load(f), candidate

    # 2. Check for embedded JSON in task
    json_match = re.search(r"(\[\s*\{.*\}\s*\])", task, re.DOTALL)
    if json_match:
        return json.loads(json_match.group(1)), "inline_json"

    # 3. Default fallback to standard ETL pipeline sample
    default_sample = [
        {"id": "extract_users", "duration": 3, "dependsOn": []},
        {"id": "extract_orders", "duration": 4, "dependsOn": []},
        {"id": "clean_users", "duration": 2, "dependsOn": ["extract_users"]},
        {"id": "clean_orders", "duration": 3, "dependsOn": ["extract_orders"]},
        {"id": "join_data", "duration": 5, "dependsOn": ["clean_users", "clean_orders"]},
        {"id": "generate_report", "duration": 2, "dependsOn": ["join_data"]},
        {"id": "publish_dashboard", "duration": 1, "dependsOn": ["generate_report"]}
    ]
    return default_sample, "default_etl_sample"


def run(task: str) -> dict:
    """
    Autonomous Agent runner conforming to hackathon specification.
    Decomposes task -> chooses tools -> executes -> produces result with HITL gate.
    """
    plan: List[str] = []
    result: Any = None
    escalated: bool = False

    # Step 1: Security Inspection
    plan.append("1. Validate input hygiene and check for prompt injection / security risks.")
    try:
        _sanitize_and_inspect_prompt(task)
    except AgentSecurityError as sec_err:
        plan.append(f"Gate Triggered: {sec_err}")
        return {
            "plan": plan,
            "result": {"status": "REJECTED_SECURITY_RISK", "details": str(sec_err)},
            "escalated": True
        }

    # Step 2: Ingest & Parse Pipeline Specification
    plan.append("2. Ingest and parse pipeline specification.")
    try:
        raw_data, source = _extract_pipeline_data(task)
        plan.append(f"   Loaded pipeline source: {source} ({len(raw_data)} jobs)")
        graph = JobGraph.from_dict_list(raw_data)
    except Exception as parse_err:
        plan.append(f"Gate Triggered: Failed to parse pipeline ({parse_err})")
        return {
            "plan": plan,
            "result": {"status": "PARSING_ERROR", "error": str(parse_err)},
            "escalated": True
        }

    # Step 3: M1 Validation (Cycle & Missing Dependency Detection)
    plan.append("3. Execute Milestone 1: Graph validation for cycles and missing dependencies.")
    val_report = graph.validate()
    if not val_report.is_valid:
        plan.append(f"   Validation failed with {len(val_report.errors)} issue(s).")
        plan.append("Gate Triggered: Escalating invalid graph to human engineer.")
        return {
            "plan": plan,
            "result": {
                "status": "VALIDATION_FAILED",
                "errors": val_report.errors,
                "missing_dependencies": val_report.missing_dependencies,
                "cycle_path": val_report.cycle_path
            },
            "escalated": True
        }

    # Step 4: Determine Action from Intent
    task_lower = task.lower()

    if "fail" in task_lower or "simulate" in task_lower:
        # M5 Failure Simulation
        plan.append("4. Execute Milestone 5: Downstream failure simulation.")
        # Find which job to fail
        target_job = None
        for jid in graph.jobs:
            if jid.lower() in task_lower:
                target_job = jid
                break
        if not target_job:
            # Default to first non-leaf or first job
            target_job = list(graph.jobs.keys())[0]

        plan.append(f"   Target failure node: '{target_job}'. Computing transitive closure.")
        fail_res = graph.simulate_failure(target_job)

        # Human in the loop gate: if impact > 50%, escalate
        if fail_res.impact_percentage > 50.0:
            plan.append(f"Gate Triggered: Failure impact ({fail_res.impact_percentage}%) exceeds safety threshold (>50%). Escalating to human on-call.")
            escalated = True

        result = {
            "failed_job": fail_res.failed_job,
            "impact_percentage": fail_res.impact_percentage,
            "skipped_jobs": fail_res.skipped_jobs,
            "executed_jobs": fail_res.executed_jobs
        }

    elif "critical" in task_lower or "makespan" in task_lower or "completion" in task_lower:
        # M4 Critical Path
        plan.append("4. Execute Milestone 4: Critical path and makespan calculation.")
        cp_res = graph.compute_critical_path()
        result = {
            "critical_path": cp_res.critical_path,
            "minimum_completion_time": cp_res.minimum_completion_time,
            "job_count": len(graph.jobs)
        }

    elif "stage" in task_lower or "worker" in task_lower or "parallel" in task_lower:
        # M3 Parallel Stages with Workers
        worker_match = re.search(r"(\d+)\s*worker", task_lower)
        workers = int(worker_match.group(1)) if worker_match else 2
        plan.append(f"4. Execute Milestone 3: Parallel stage grouping (worker limit = {workers}).")
        stages = graph.get_parallel_stages(max_workers=workers)
        discrete_sim = graph.simulate_worker_execution(max_workers=workers)
        result = {
            "worker_limit": workers,
            "stages": stages,
            "simulated_makespan": discrete_sim["makespan"],
            "timeline": discrete_sim["timeline"]
        }

    else:
        # M2 Topological Sort Order (Default)
        plan.append("4. Execute Milestone 2: Topological sort execution ordering.")
        topo_order = graph.topological_sort()
        cp_res = graph.compute_critical_path()
        stages = graph.get_parallel_stages()
        result = {
            "topological_order": topo_order,
            "stages": stages,
            "critical_path": cp_res.critical_path,
            "minimum_completion_time": cp_res.minimum_completion_time
        }

    plan.append("5. Synthesize final execution output and conclude.")
    return {
        "plan": plan,
        "result": result,
        "escalated": escalated
    }


if __name__ == "__main__":
    test_task = "Run pipeline analysis on pipeline_complex_etl.json with 2 workers and compute critical path."
    output = run(test_task)
    print(json.dumps(output, indent=2))
