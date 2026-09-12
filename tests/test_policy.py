from guarded_agent_runner.capability import compile_scope
from guarded_agent_runner.models import PolicyDecision, ToolCall
from guarded_agent_runner.policy.policy_engine import PolicyEngine


def test_out_of_scope_service_is_denied():
    result = PolicyEngine().safe_evaluate(
        ToolCall(action="restart_service", args={"service": "ssh"}),
        compile_scope(),
    )
    assert result.decision is PolicyDecision.DENY_OUT_OF_SCOPE


def test_unknown_action_is_denied():
    result = PolicyEngine().safe_evaluate(
        ToolCall(action="run_shell", args={"service": "nginx"}),
        compile_scope(),
    )
    assert result.decision is PolicyDecision.DENY_UNKNOWN_ACTION


def test_malformed_tool_call_is_denied():
    result = PolicyEngine().safe_evaluate(
        ToolCall(action="read_log", args={"service": "nginx", "lines": "all"}),
        compile_scope(),
    )
    assert result.decision is PolicyDecision.DENY_INVALID_ARGUMENTS


def test_missing_scope_is_denied():
    result = PolicyEngine().safe_evaluate(
        ToolCall(action="service_status", args={"service": "nginx"}),
        None,
    )
    assert result.decision is PolicyDecision.DENY_INVALID_SCOPE
