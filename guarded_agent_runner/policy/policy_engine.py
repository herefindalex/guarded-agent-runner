from __future__ import annotations

from guarded_agent_runner.capability import assert_scope_integrity
from guarded_agent_runner.models import (
    ApprovalMode,
    CapabilityScope,
    PolicyDecision,
    PolicyResult,
    ToolCall,
)

KNOWN_ACTIONS = {"service_status", "read_log", "restart_service"}


class PolicyEngine:
    def __init__(self, *, force_failure: bool = False) -> None:
        self.force_failure = force_failure

    def evaluate(self, call: ToolCall, scope: CapabilityScope | None) -> PolicyResult:
        if self.force_failure:
            raise RuntimeError("Injected policy service failure")
        if scope is None:
            return PolicyResult(
                decision=PolicyDecision.DENY_INVALID_SCOPE,
                reason="Required capability scope is missing",
            )
        try:
            assert_scope_integrity(scope)
        except (TypeError, ValueError) as exc:
            return PolicyResult(decision=PolicyDecision.DENY_INVALID_SCOPE, reason=str(exc))
        if call.action not in KNOWN_ACTIONS:
            return PolicyResult(
                decision=PolicyDecision.DENY_UNKNOWN_ACTION,
                reason=f"Unknown action: {call.action}",
            )
        if call.action not in scope.allowed_actions:
            return PolicyResult(
                decision=PolicyDecision.DENY_OUT_OF_SCOPE,
                reason=f"Action is outside capability scope: {call.action}",
            )
        validation_error = self._validate_args(call)
        if validation_error:
            return PolicyResult(
                decision=PolicyDecision.DENY_INVALID_ARGUMENTS,
                reason=validation_error,
            )
        if call.resource not in scope.allowed_services:
            return PolicyResult(
                decision=PolicyDecision.DENY_OUT_OF_SCOPE,
                reason=f"Resource is outside capability scope: {call.resource}",
            )
        mode = scope.mode_for(call.action)
        if mode is ApprovalMode.AUTO:
            return PolicyResult(decision=PolicyDecision.ALLOW_AUTO, reason="Low-risk action")
        if mode is ApprovalMode.REQUIRED:
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reason="Privileged action requires exact human approval",
            )
        return PolicyResult(
            decision=PolicyDecision.DENY_INVALID_SCOPE,
            reason="Approval policy is missing; default deny",
        )

    def safe_evaluate(self, call: ToolCall, scope: CapabilityScope | None) -> PolicyResult:
        try:
            return self.evaluate(call, scope)
        except Exception:
            return PolicyResult(
                decision=PolicyDecision.DENY_INTERNAL_ERROR,
                reason="Policy evaluation failed; default deny",
            )

    @staticmethod
    def _validate_args(call: ToolCall) -> str | None:
        expected = {"service"} if call.action != "read_log" else {"service", "lines"}
        if set(call.args) != expected:
            return f"Expected exact arguments: {sorted(expected)}"
        if not isinstance(call.args.get("service"), str) or not call.args["service"]:
            return "service must be a non-empty string"
        if call.action == "read_log":
            lines = call.args.get("lines")
            if isinstance(lines, bool) or not isinstance(lines, int) or not 1 <= lines <= 1000:
                return "lines must be an integer between 1 and 1000"
        return None
