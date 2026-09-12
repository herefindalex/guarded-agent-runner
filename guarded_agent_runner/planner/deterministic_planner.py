from __future__ import annotations

from guarded_agent_runner.models import PlanPreset, ServiceName, ToolCall


class DeterministicPlanner:
    """An intentionally untrusted, credential-free and reproducible planner."""

    def __init__(self, forced_plan: list[ToolCall] | None = None) -> None:
        self._forced_plan = forced_plan

    def plan(
        self,
        request: str,
        workflow: PlanPreset = PlanPreset.DIAGNOSE_AND_RESTART,
        service: ServiceName = ServiceName.NGINX,
    ) -> list[ToolCall]:
        del request  # The MVP deliberately avoids probabilistic interpretation.
        if self._forced_plan is not None:
            return [call.model_copy(deep=True) for call in self._forced_plan]
        calls = {
            PlanPreset.STATUS_ONLY: [
                ToolCall(
                    action="service_status",
                    args={"service": service.value},
                    purpose="observe_current_state",
                ),
            ],
            PlanPreset.LOGS_ONLY: [
                ToolCall(
                    action="read_log",
                    args={"service": service.value, "lines": 100},
                    purpose="inspect_recent_evidence",
                ),
            ],
            PlanPreset.STATUS_AND_LOGS: [
                ToolCall(
                    action="service_status",
                    args={"service": service.value},
                    purpose="observe_current_state",
                ),
                ToolCall(
                    action="read_log",
                    args={"service": service.value, "lines": 100},
                    purpose="inspect_recent_evidence",
                ),
            ],
            PlanPreset.DIAGNOSE_AND_RESTART: [
                ToolCall(
                    action="service_status",
                    args={"service": service.value},
                    purpose="diagnose_current_state",
                ),
                ToolCall(
                    action="read_log",
                    args={"service": service.value, "lines": 100},
                    purpose="inspect_recent_evidence",
                ),
                ToolCall(
                    action="restart_service",
                    args={"service": service.value},
                    purpose="remediate_if_needed",
                ),
                ToolCall(
                    action="service_status",
                    args={"service": service.value},
                    purpose="verify_outcome",
                ),
            ],
        }
        return calls[workflow]
