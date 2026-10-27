"""
Job Scheduler with Dependency Resolution (DAG) Engine.
Addresses Milestones M1 through M5 and beyond for SDSI PS5.

Features:
- M1: Graph validation, missing dependency detection, exact cycle path reporting.
- M2: Topological sort (Kahn's algorithm) with deterministic tie-breaking.
- M3: Parallel stages computation with configurable worker limit N.
- M4: Critical path calculation, slack analysis, and minimum completion time (makespan).
- M5: Failure propagation simulation (transitive downstream skipped jobs).
- Stretch: Discrete-event worker pool scheduling, ASCII & Mermaid visualizers,
  rich timing telemetry, strict schema validation, and edge-case resilience.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
import json
from collections import defaultdict, deque
import heapq


class SchedulerError(Exception):
    """Base exception for scheduler-related errors."""
    pass


class ValidationError(SchedulerError):
    """Raised when the job graph fails schema, dependency, or cycle validation."""
    pass


@dataclass
class Job:
    """Represents an atomic job node within the orchestrator DAG."""
    id: str
    duration: float
    depends_on: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValidationError(f"Job id must be a non-empty string. Got: {repr(self.id)}")
        
        # Security sanitization: prevent null byte injection or abnormal characters
        if "\x00" in self.id:
            raise ValidationError(f"Job id contains invalid null byte: {repr(self.id)}")
            
        try:
            self.duration = float(self.duration)
        except (ValueError, TypeError):
            raise ValidationError(f"Job '{self.id}' duration must be a valid non-negative number. Got: {repr(self.duration)}")
            
        if self.duration < 0:
            raise ValidationError(f"Job '{self.id}' duration cannot be negative: {self.duration}")
            
        if not isinstance(self.depends_on, list):
            raise ValidationError(f"Job '{self.id}' dependsOn must be a list of job IDs.")
            
        for dep in self.depends_on:
            if not isinstance(dep, str) or not dep.strip():
                raise ValidationError(f"Job '{self.id}' contains invalid dependency ID: {repr(dep)}")


@dataclass
class ValidationReport:
    """Detailed validation outcome including any missing dependencies or cycle paths."""
    is_valid: bool
    missing_dependencies: Dict[str, List[str]] = field(default_factory=dict)  # missing_id -> [jobs that depend on it]
    cycle_path: Optional[List[str]] = None
    errors: List[str] = field(default_factory=list)


@dataclass
class JobTiming:
    """Calculated start/finish and slack metrics for critical path analysis."""
    job_id: str
    duration: float
    earliest_start: float
    earliest_finish: float
    latest_start: float
    latest_finish: float
    slack: float
    is_critical: bool


@dataclass
class CriticalPathResult:
    """Summary of critical path evaluation."""
    critical_path: List[str]
    minimum_completion_time: float
    job_timings: Dict[str, JobTiming]


@dataclass
class FailureSimulationResult:
    """Result of simulating a single or multi-job failure event."""
    failed_job: str
    skipped_jobs: List[str]
    executed_jobs: List[str]
    total_jobs: int
    impact_percentage: float


class JobGraph:
    """
    DAG representation and execution analysis engine for Job Scheduler.
    Handles dependency validation, topological execution planning, worker leveling,
    critical path calculations, and fault simulation.
    """

    def __init__(self, jobs: List[Job]):
        self.jobs: Dict[str, Job] = {}
        for job in jobs:
            if job.id in self.jobs:
                raise ValidationError(f"Duplicate job id detected: '{job.id}'")
            self.jobs[job.id] = job

        # Forward adjacency: u -> list of jobs that depend on u
        self.adj: Dict[str, List[str]] = defaultdict(list)
        # Reverse adjacency: u -> list of jobs u depends on
        self.reverse_adj: Dict[str, List[str]] = defaultdict(list)
        # In-degree count (number of prerequisites)
        self.in_degree: Dict[str, int] = {jid: 0 for jid in self.jobs}

        for jid, job in self.jobs.items():
            for dep in job.depends_on:
                self.reverse_adj[jid].append(dep)
                if dep in self.jobs:
                    self.adj[dep].append(jid)
                    self.in_degree[jid] += 1

    @classmethod
    def from_dict_list(cls, data: List[Dict[str, Any]]) -> "JobGraph":
        """Instantiate JobGraph from raw JSON dict list with validation."""
        if not isinstance(data, list):
            raise ValidationError("Input must be a JSON array of job objects.")
        jobs = []
        for item in data:
            if not isinstance(item, dict):
                raise ValidationError(f"Job entry must be a dictionary. Got: {type(item).__name__}")
            jid = item.get("id") or item.get("name")
            if not jid:
                raise ValidationError("Job object missing required 'id' or 'name' field.")
            duration = item.get("duration", 0)
            depends_on = item.get("dependsOn", item.get("depends_on", []))
            metadata = {k: v for k, v in item.items() if k not in ("id", "name", "duration", "dependsOn", "depends_on")}
            jobs.append(Job(id=str(jid), duration=duration, depends_on=list(depends_on), metadata=metadata))
        return cls(jobs)

    @classmethod
    def from_json_str(cls, json_str: str) -> "JobGraph":
        """Instantiate JobGraph directly from JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as err:
            raise ValidationError(f"Malformed JSON payload: {err.msg} at line {err.lineno} col {err.colno}")
        return cls.from_dict_list(data)

    # -------------------------------------------------------------------------
    # M1: Graph Validation (Cycles & Missing Dependencies)
    # -------------------------------------------------------------------------
    def validate(self) -> ValidationReport:
        """
        Validates graph structure:
        - Detects missing dependencies (referenced in dependsOn but not declared).
        - Detects cycles using 3-color DFS and extracts the exact cycle path.
        """
        errors: List[str] = []
        missing_deps: Dict[str, List[str]] = defaultdict(list)

        # 1. Missing dependencies check
        for jid, job in self.jobs.items():
            for dep in job.depends_on:
                if dep not in self.jobs:
                    missing_deps[dep].append(jid)
                    errors.append(f"Job '{jid}' depends on undeclared job '{dep}'")

        # 2. Cycle detection via 3-color DFS
        # 0: WHITE (unvisited), 1: GRAY (in recursion stack), 2: BLACK (fully visited)
        visited: Dict[str, int] = {jid: 0 for jid in self.jobs}
        cycle_path: Optional[List[str]] = None
        call_stack: List[str] = []

        def dfs(u: str) -> bool:
            nonlocal cycle_path
            visited[u] = 1
            call_stack.append(u)

            # Follow dependencies: if u depends on dep, execution requires dep -> u.
            # A cycle exists if dep is currently in call_stack.
            # Here we traverse in execution flow: dep -> u
            for v in self.adj.get(u, []):
                if visited[v] == 1:
                    # Found cycle: v is an ancestor in current recursion branch
                    cycle_start_idx = call_stack.index(v)
                    cycle_path = call_stack[cycle_start_idx:] + [v]
                    return True
                elif visited[v] == 0:
                    if dfs(v):
                        return True

            call_stack.pop()
            visited[u] = 2
            return False

        # Check self-loops first
        for jid, job in self.jobs.items():
            if jid in job.depends_on:
                cycle_path = [jid, jid]
                errors.append(f"Self-referencing cycle detected: {jid} -> {jid}")
                break

        if not cycle_path:
            # Deterministic iteration order
            for node in sorted(self.jobs.keys()):
                if visited[node] == 0:
                    if dfs(node):
                        errors.append(f"Cycle detected: {' -> '.join(cycle_path)}")
                        break

        is_valid = len(errors) == 0
        return ValidationReport(
            is_valid=is_valid,
            missing_dependencies=dict(missing_deps),
            cycle_path=cycle_path,
            errors=errors
        )

    # -------------------------------------------------------------------------
    # M2: Topological Sort
    # -------------------------------------------------------------------------
    def topological_sort(self) -> List[str]:
        """
        Produces a valid linear execution order using Kahn's algorithm.
        Employs deterministic tie-breaking (lexicographical) for reproducibility.
        Raises ValidationError if graph has cycles or missing dependencies.
        """
        report = self.validate()
        if not report.is_valid:
            raise ValidationError(f"Cannot perform topological sort on invalid graph: {'; '.join(report.errors)}")

        in_deg = dict(self.in_degree)
        ready_queue: List[str] = [jid for jid, deg in in_deg.items() if deg == 0]
        heapq.heapify(ready_queue)  # Deterministic min-heap ordering

        execution_order: List[str] = []

        while ready_queue:
            u = heapq.heappop(ready_queue)
            execution_order.append(u)

            for neighbor in sorted(self.adj.get(u, [])):
                in_deg[neighbor] -= 1
                if in_deg[neighbor] == 0:
                    heapq.heappush(ready_queue, neighbor)

        if len(execution_order) != len(self.jobs):
            raise ValidationError("Topological sort failed: Unresolvable cyclic dependencies remain.")

        return execution_order

    # -------------------------------------------------------------------------
    # M3: Parallel Stages with Configurable Worker Limit N
    # -------------------------------------------------------------------------
    def get_parallel_stages(self, max_workers: Optional[int] = None) -> List[List[str]]:
        """
        Groups jobs into parallel execution stages.
        Jobs in each stage are independent of each other and have all prerequisites satisfied
        in prior stages.
        If max_workers is set, each stage is chunked to never exceed N concurrent jobs.
        """
        if max_workers is not None:
            if not isinstance(max_workers, int) or max_workers <= 0:
                raise ValidationError(f"max_workers must be a positive integer. Got: {repr(max_workers)}")

        # Validate graph
        self.topological_sort()  # Will raise if invalid

        # Calculate logical levels (longest edge distance from root)
        levels: Dict[str, int] = {}
        for jid in self.topological_sort():
            deps = self.jobs[jid].depends_on
            if not deps:
                levels[jid] = 0
            else:
                levels[jid] = 1 + max(levels[d] for d in deps)

        # Group by level
        grouped_by_level: Dict[int, List[str]] = defaultdict(list)
        for jid, lvl in levels.items():
            grouped_by_level[lvl].append(jid)

        stages: List[List[str]] = []
        for lvl in sorted(grouped_by_level.keys()):
            current_stage_jobs = sorted(grouped_by_level[lvl])
            if max_workers is None or len(current_stage_jobs) <= max_workers:
                stages.append(current_stage_jobs)
            else:
                # Chunk into batches of size <= max_workers
                for i in range(0, len(current_stage_jobs), max_workers):
                    stages.append(current_stage_jobs[i:i + max_workers])

        return stages

    # -------------------------------------------------------------------------
    # M4: Critical Path & Minimum Total Completion Time (Makespan)
    # -------------------------------------------------------------------------
    def compute_critical_path(self) -> CriticalPathResult:
        """
        Calculates earliest and latest event schedules using forward/backward pass.
        Identifies:
        - Minimum total completion time (unbounded parallel makespan).
        - Critical Path: Sequence of dependent jobs where slack == 0.
        """
        order = self.topological_sort()
        if not order:
            return CriticalPathResult(critical_path=[], minimum_completion_time=0.0, job_timings={})

        earliest_start: Dict[str, float] = {}
        earliest_finish: Dict[str, float] = {}

        # Forward Pass
        for jid in order:
            job = self.jobs[jid]
            if not job.depends_on:
                es = 0.0
            else:
                es = max(earliest_finish[dep] for dep in job.depends_on)
            earliest_start[jid] = es
            earliest_finish[jid] = es + job.duration

        makespan = max(earliest_finish.values()) if earliest_finish else 0.0

        # Backward Pass
        latest_finish: Dict[str, float] = {}
        latest_start: Dict[str, float] = {}

        for jid in reversed(order):
            job = self.jobs[jid]
            dependents = self.adj.get(jid, [])
            if not dependents:
                lf = makespan
            else:
                lf = min(latest_start[dep] for dep in dependents)
            latest_finish[jid] = lf
            latest_start[jid] = lf - job.duration

        # Compute Slack & Build Timings
        timings: Dict[str, JobTiming] = {}
        for jid in order:
            dur = self.jobs[jid].duration
            es = earliest_start[jid]
            ef = earliest_finish[jid]
            ls = latest_start[jid]
            lf = latest_finish[jid]
            slack = round(ls - es, 6)
            is_crit = abs(slack) < 1e-9
            timings[jid] = JobTiming(
                job_id=jid,
                duration=dur,
                earliest_start=es,
                earliest_finish=ef,
                latest_start=ls,
                latest_finish=lf,
                slack=max(0.0, slack),
                is_critical=is_crit
            )

        # Trace primary critical path from start to makespan finish
        critical_path: List[str] = []
        # Find terminal critical node with ef == makespan
        terminal_nodes = [j for j, t in timings.items() if t.is_critical and abs(t.earliest_finish - makespan) < 1e-9]
        if terminal_nodes:
            curr = sorted(terminal_nodes)[0]
            critical_path.append(curr)
            while self.jobs[curr].depends_on:
                # Predecessor on critical path whose EF matches curr's ES
                curr_es = timings[curr].earliest_start
                crit_preds = [
                    p for p in self.jobs[curr].depends_on
                    if timings[p].is_critical and abs(timings[p].earliest_finish - curr_es) < 1e-9
                ]
                if not crit_preds:
                    break
                curr = sorted(crit_preds)[0]
                critical_path.append(curr)

            critical_path.reverse()

        return CriticalPathResult(
            critical_path=critical_path,
            minimum_completion_time=makespan,
            job_timings=timings
        )

    # -------------------------------------------------------------------------
    # M5: Failure Simulation (Downstream Impact)
    # -------------------------------------------------------------------------
    def simulate_failure(self, failed_job_id: str) -> FailureSimulationResult:
        """
        Simulates failure of a specific job:
        - Discovers all transitive downstream jobs that cannot execute.
        - Identifies all unaffected jobs that can safely run.
        """
        if failed_job_id not in self.jobs:
            raise ValidationError(f"Cannot simulate failure for non-existent job: '{failed_job_id}'")

        # Transitive downstream reachability via BFS
        skipped: Set[str] = set()
        queue = deque([failed_job_id])

        while queue:
            curr = queue.popleft()
            for child in self.adj.get(curr, []):
                if child not in skipped:
                    skipped.add(child)
                    queue.append(child)

        # Sort skipped in topological order for clean inspection
        full_order = self.topological_sort()
        ordered_skipped = [jid for jid in full_order if jid in skipped]
        ordered_executed = [jid for jid in full_order if jid not in skipped and jid != failed_job_id]

        total = len(self.jobs)
        impact = (len(skipped) + 1) / total * 100.0 if total > 0 else 0.0

        return FailureSimulationResult(
            failed_job=failed_job_id,
            skipped_jobs=ordered_skipped,
            executed_jobs=ordered_executed,
            total_jobs=total,
            impact_percentage=round(impact, 2)
        )

    # -------------------------------------------------------------------------
    # Stretch / Bonus: Discrete-Event Worker-Pool Simulator
    # -------------------------------------------------------------------------
    def simulate_worker_execution(self, max_workers: int) -> Dict[str, Any]:
        """
        Simulates true real-time dispatch across N worker threads/processes.
        Provides worker Gantt assignments, start/end timestamps, and constrained makespan.
        """
        if not isinstance(max_workers, int) or max_workers <= 0:
            raise ValidationError(f"max_workers must be positive integer. Got: {max_workers}")

        self.topological_sort()  # Validate

        in_deg = dict(self.in_degree)
        ready: List[str] = [j for j, d in in_deg.items() if d == 0]
        heapq.heapify(ready)

        free_workers: List[int] = list(range(1, max_workers + 1))
        heapq.heapify(free_workers)

        # Priority queue of events: (time, event_type, worker_id, job_id)
        # event_type: 0 for job completion
        events: List[Tuple[float, int, int, str]] = []

        job_records: Dict[str, Dict[str, Any]] = {}
        current_time = 0.0

        while ready or events:
            # Dispatch all possible ready jobs to available workers
            while ready and free_workers:
                job_id = heapq.heappop(ready)
                worker_id = heapq.heappop(free_workers)
                dur = self.jobs[job_id].duration
                start_t = current_time
                finish_t = start_t + dur
                job_records[job_id] = {
                    "job_id": job_id,
                    "worker": f"Worker-{worker_id}",
                    "start": start_t,
                    "finish": finish_t,
                    "duration": dur
                }
                heapq.heappush(events, (finish_t, 0, worker_id, job_id))

            if not events:
                break

            # Advance clock to next event
            finish_t, _, worker_id, completed_job = heapq.heappop(events)
            current_time = finish_t
            heapq.heappush(free_workers, worker_id)

            # Unlock dependents
            for dependent in sorted(self.adj.get(completed_job, [])):
                in_deg[dependent] -= 1
                if in_deg[dependent] == 0:
                    heapq.heappush(ready, dependent)

        return {
            "max_workers": max_workers,
            "makespan": current_time,
            "timeline": sorted(job_records.values(), key=lambda r: (r["start"], r["job_id"]))
        }

    # -------------------------------------------------------------------------
    # Visualizer Exporters (Mermaid & ASCII)
    # -------------------------------------------------------------------------
    def export_mermaid(self) -> str:
        """Generates Mermaid diagram string with critical path highlighted."""
        lines = ["flowchart TD"]
        crit_res = self.compute_critical_path()
        crit_set = set(crit_res.critical_path)

        for jid, job in sorted(self.jobs.items()):
            label = f"{jid} [{job.duration}s]"
            if jid in crit_set:
                lines.append(f'    {jid}["{label}"]:::critical')
            else:
                lines.append(f'    {jid}["{label}"]')

        for u in sorted(self.jobs.keys()):
            for v in sorted(self.adj.get(u, [])):
                if u in crit_set and v in crit_set and crit_res.critical_path.index(v) == crit_res.critical_path.index(u) + 1:
                    lines.append(f"    {u} ==>|critical| {v}")
                else:
                    lines.append(f"    {u} --> {v}")

        lines.append("    classDef critical fill:#ffcccc,stroke:#ff0000,stroke-width:2px;")
        return "\n".join(lines)
