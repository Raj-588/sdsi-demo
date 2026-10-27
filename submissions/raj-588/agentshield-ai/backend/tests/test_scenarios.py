"""End-to-end scenario regression tests (attacks A–F + legit).

Each runs the full task -> agent -> gateway path and asserts the expected
decision for the scenario's critical tool call.
"""
from __future__ import annotations

import pytest

from app.schemas.models import AgentRunRequest, TaskCreate
from app.services import agent_service, task_service
from app.services.scenarios import SCENARIOS

USER = "user-demo-001"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_scenario_expected_decision(db, scenario):
    task = task_service.create_task(
        db,
        TaskCreate(template_id=scenario["template_id"], original_request=""),
        user_id=USER,
    )
    resp = agent_service.run_agent(
        db,
        task_id=task.id,
        user_request=scenario["user_request"],
        document_name=scenario.get("document_name"),
        document_content=scenario.get("document_content", ""),
        scenario_id=scenario.get("scenario_hint"),
    )
    attack_tool = scenario["attack_tool"]
    matching = [c for c in resp.evaluated_calls if c.call.tool == attack_tool]
    assert matching, f"agent did not propose expected tool {attack_tool}"
    decisions = {c.decision for c in matching}
    assert scenario["expected_for_attack_call"] in decisions, (
        f"{scenario['id']}: expected {scenario['expected_for_attack_call']} "
        f"for {attack_tool}, got {decisions}"
    )


def test_blocked_scenarios_never_execute(db):
    """For every DENY/APPROVAL scenario, no blocked call returns a result."""
    for scenario in SCENARIOS:
        if scenario["expected_for_attack_call"].value == "ALLOW":
            continue
        task = task_service.create_task(
            db, TaskCreate(template_id=scenario["template_id"], original_request=""),
            user_id=USER,
        )
        resp = agent_service.run_agent(
            db, task_id=task.id, user_request=scenario["user_request"],
            document_name=scenario.get("document_name"),
            document_content=scenario.get("document_content", ""),
            scenario_id=scenario.get("scenario_hint"),
        )
        for c in resp.evaluated_calls:
            if c.call.tool == scenario["attack_tool"] and c.decision.value != "ALLOW":
                assert c.result is None
                assert c.execution_status.value == "BLOCKED"
