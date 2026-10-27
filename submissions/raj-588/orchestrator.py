#!/usr/bin/env python3
"""
Orchestrator CLI for Job Scheduler with Dependency Resolution (DAG).
Allows executing, analyzing, validating, and simulating DAG pipelines from JSON files or STDIN.

Usage:
  python orchestrator.py validate -f pipeline.json
  python orchestrator.py plan -f pipeline.json
  python orchestrator.py stages -f pipeline.json -w 2
  python orchestrator.py critical-path -f pipeline.json
  python orchestrator.py simulate-failure -f pipeline.json --fail-job build_backend
  python orchestrator.py run -f pipeline.json -w 3
  python orchestrator.py mermaid -f pipeline.json
"""

import argparse
import json
import sys
import os
from typing import Any, Dict

# Ensure local submission directory is in sys.path
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if _CURRENT_DIR not in sys.path:
    sys.path.insert(0, _CURRENT_DIR)

from scheduler import JobGraph, SchedulerError, ValidationError


def load_json_input(file_path: str = None) -> str:
    """Safely loads pipeline definition from file or stdin."""
    if file_path:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Specified pipeline file does not exist: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    else:
        if sys.stdin.isatty():
            raise ValueError("No file provided and STDIN is empty. Pass -f <filename> or pipe JSON.")
        return sys.stdin.read()


def cmd_validate(graph: JobGraph, args: argparse.Namespace) -> int:
    """M1: Validates graph structure and reports cycles / missing dependencies."""
    report = graph.validate()
    output = {
        "is_valid": report.is_valid,
        "job_count": len(graph.jobs),
        "errors": report.errors,
        "missing_dependencies": report.missing_dependencies,
        "cycle_path": report.cycle_path
    }
    if args.json:
        print(json.dumps(output, indent=2))
    else:
        if report.is_valid:
            print(f"[SUCCESS] DAG is valid. Total jobs: {len(graph.jobs)}.")
        else:
            print(f"[FAILURE] DAG validation failed with {len(report.errors)} issue(s):")
            for err in report.errors:
                print(f"  - {err}")
            if report.cycle_path:
                print(f"  Cycle loop: {' -> '.join(report.cycle_path)}")
    return 0 if report.is_valid else 1


def cmd_plan(graph: JobGraph, args: argparse.Namespace) -> int:
    """M2: Produces topological sort execution order."""
    try:
        order = graph.topological_sort()
        if args.json:
            print(json.dumps({"topological_order": order}, indent=2))
        else:
            print(f"[EXECUTION ORDER] Deterministic Topological Sort ({len(order)} jobs):")
            for idx, jid in enumerate(order, 1):
                deps = graph.jobs[jid].depends_on
                dep_str = f" (depends on: {', '.join(deps)})" if deps else " (root)"
                print(f"  {idx:2d}. {jid:20s} [duration: {graph.jobs[jid].duration:.1f}s]{dep_str}")
        return 0
    except ValidationError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_stages(graph: JobGraph, args: argparse.Namespace) -> int:
    """M3: Computes parallel stages with optional worker limit."""
    try:
        stages = graph.get_parallel_stages(max_workers=args.workers)
        if args.json:
            print(json.dumps({
                "worker_limit": args.workers,
                "stage_count": len(stages),
                "stages": stages
            }, indent=2))
        else:
            limit_str = f" (Worker limit: {args.workers})" if args.workers else " (Unbounded workers)"
            print(f"[PARALLEL STAGES]{limit_str} Total stages: {len(stages)}")
            for idx, stage in enumerate(stages, 1):
                jobs_detail = [f"{j} ({graph.jobs[j].duration:.1f}s)" for j in stage]
                print(f"  Stage {idx:2d} ({len(stage)} jobs): {', '.join(jobs_detail)}")
        return 0
    except ValidationError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_critical_path(graph: JobGraph, args: argparse.Namespace) -> int:
    """M4: Evaluates critical path and makespan."""
    try:
        res = graph.compute_critical_path()
        if args.json:
            timings_dict = {
                k: {
                    "duration": v.duration,
                    "earliest_start": v.earliest_start,
                    "earliest_finish": v.earliest_finish,
                    "latest_start": v.latest_start,
                    "latest_finish": v.latest_finish,
                    "slack": v.slack,
                    "is_critical": v.is_critical
                }
                for k, v in res.job_timings.items()
            }
            print(json.dumps({
                "critical_path": res.critical_path,
                "minimum_completion_time": res.minimum_completion_time,
                "job_timings": timings_dict
            }, indent=2))
        else:
            print(f"[CRITICAL PATH ANALYSIS]")
            print(f"  Minimum Total Completion Time (Makespan): {res.minimum_completion_time:.2f}s")
            print(f"  Critical Path: {' -> '.join(res.critical_path)}")
            print("\n  Schedule & Slack Breakdown:")
            print(f"  {'Job ID':<20} {'Dur':<6} {'ES':<6} {'EF':<6} {'LS':<6} {'LF':<6} {'Slack':<6} {'Critical'}")
            print("  " + "-" * 66)
            for jid, t in sorted(res.job_timings.items()):
                crit_flag = "YES (*)" if t.is_critical else "NO"
                print(f"  {jid:<20} {t.duration:<6.1f} {t.earliest_start:<6.1f} {t.earliest_finish:<6.1f} {t.latest_start:<6.1f} {t.latest_finish:<6.1f} {t.slack:<6.1f} {crit_flag}")
        return 0
    except ValidationError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_simulate_failure(graph: JobGraph, args: argparse.Namespace) -> int:
    """M5: Simulates downstream failure cascade."""
    if not args.fail_job:
        print("[ERROR] Must provide --fail-job <job_id> to simulate failure.", file=sys.stderr)
        return 1
    try:
        res = graph.simulate_failure(args.fail_job)
        if args.json:
            print(json.dumps({
                "failed_job": res.failed_job,
                "total_jobs": res.total_jobs,
                "impact_percentage": res.impact_percentage,
                "skipped_jobs_count": len(res.skipped_jobs),
                "skipped_jobs": res.skipped_jobs,
                "executed_jobs_count": len(res.executed_jobs),
                "executed_jobs": res.executed_jobs
            }, indent=2))
        else:
            print(f"[FAILURE SIMULATION: '{res.failed_job}']")
            print(f"  Impact: {res.impact_percentage}% of DAG affected")
            print(f"  Skipped downstream jobs ({len(res.skipped_jobs)}): {', '.join(res.skipped_jobs) if res.skipped_jobs else 'None'}")
            print(f"  Successfully runnable jobs ({len(res.executed_jobs)}): {', '.join(res.executed_jobs) if res.executed_jobs else 'None'}")
        return 0
    except ValidationError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_run(graph: JobGraph, args: argparse.Namespace) -> int:
    """Stretch: Runs discrete-event simulated execution."""
    try:
        workers = args.workers or 4
        sim = graph.simulate_worker_execution(max_workers=workers)
        if args.json:
            print(json.dumps(sim, indent=2))
        else:
            print(f"[DISCRETE EVENT EXECUTION SIMULATION] Workers: {workers}")
            print(f"  Constrained Makespan: {sim['makespan']:.2f}s")
            print("\n  Execution Timeline:")
            for rec in sim["timeline"]:
                bar = "#" * int(rec["duration"])
                print(f"  [{rec['start']:5.1f}s - {rec['finish']:5.1f}s] {rec['worker']:<10} -> {rec['job_id']:<20} ({rec['duration']}s) {bar}")
        return 0
    except ValidationError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def cmd_mermaid(graph: JobGraph, args: argparse.Namespace) -> int:
    """Stretch: Generates Mermaid visualization."""
    try:
        print(graph.export_mermaid())
        return 0
    except ValidationError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1


def main():
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("-f", "--file", help="Path to pipeline JSON definition")
    common_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON format")

    parser = argparse.ArgumentParser(
        description="DAG Job Scheduler & Orchestrator (SDSI PS5)",
        parents=[common_parser]
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommands with inherited parent arguments
    subparsers.add_parser("validate", parents=[common_parser], help="M1: Validate DAG (detect cycles & missing dependencies)")
    subparsers.add_parser("plan", parents=[common_parser], help="M2: Produce deterministic topological sort order")
    
    sub_stages = subparsers.add_parser("stages", parents=[common_parser], help="M3: Group jobs into parallel stages")
    sub_stages.add_argument("-w", "--workers", type=int, default=None, help="Configurable worker concurrency limit")

    subparsers.add_parser("critical-path", parents=[common_parser], help="M4: Compute critical path and minimum completion time")

    sub_fail = subparsers.add_parser("simulate-failure", parents=[common_parser], help="M5: Simulate job failure and list skipped jobs")
    sub_fail.add_argument("--fail-job", required=True, help="Job ID that simulates failure")

    sub_run = subparsers.add_parser("run", parents=[common_parser], help="Bonus: Simulate discrete-event worker pool execution")
    sub_run.add_argument("-w", "--workers", type=int, default=2, help="Number of worker threads")

    subparsers.add_parser("mermaid", parents=[common_parser], help="Bonus: Export Mermaid DAG graph")

    args = parser.parse_args()

    try:
        json_content = load_json_input(args.file)
        graph = JobGraph.from_json_str(json_content)
    except Exception as e:
        print(f"[FATAL ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    dispatch = {
        "validate": cmd_validate,
        "plan": cmd_plan,
        "stages": cmd_stages,
        "critical-path": cmd_critical_path,
        "simulate-failure": cmd_simulate_failure,
        "run": cmd_run,
        "mermaid": cmd_mermaid
    }

    exit_code = dispatch[args.command](graph, args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
