import pytest

from guarded_agent_runner.models import PlanPreset, ServiceName
from guarded_agent_runner.planner.deterministic_planner import DeterministicPlanner


@pytest.mark.parametrize(
    ("workflow", "expected_actions"),
    [
        (PlanPreset.STATUS_ONLY, ["service_status"]),
        (PlanPreset.LOGS_ONLY, ["read_log"]),
        (PlanPreset.STATUS_AND_LOGS, ["service_status", "read_log"]),
        (
            PlanPreset.DIAGNOSE_AND_RESTART,
            ["service_status", "read_log", "restart_service", "service_status"],
        ),
    ],
)
def test_workflow_presets_generate_exact_plans(workflow, expected_actions):
    plan = DeterministicPlanner().plan("UI display text is not authorization", workflow)
    assert [call.action for call in plan] == expected_actions


def test_diagnose_restart_plan_expresses_decision_and_verification_purposes():
    plan = DeterministicPlanner().plan(
        "Restart only when needed",
        PlanPreset.DIAGNOSE_AND_RESTART,
        ServiceName.POSTGRESQL,
    )

    assert [call.purpose for call in plan] == [
        "diagnose_current_state",
        "inspect_recent_evidence",
        "remediate_if_needed",
        "verify_outcome",
    ]


@pytest.mark.parametrize("service", list(ServiceName))
def test_service_selection_is_compiled_into_every_tool_call(service):
    plan = DeterministicPlanner().plan(
        "The selected service is explicit user input",
        PlanPreset.DIAGNOSE_AND_RESTART,
        service,
    )
    assert {call.resource for call in plan} == {service.value}
