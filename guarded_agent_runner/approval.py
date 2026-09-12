from __future__ import annotations

from datetime import timedelta

from guarded_agent_runner.models import (
    ApprovalRequest,
    ApprovalStatus,
    PolicyDecision,
    Run,
    ToolCall,
    utcnow,
)
from guarded_agent_runner.policy.policy_engine import PolicyEngine


def create_approval(run: Run, call: ToolCall, ttl_seconds: float) -> ApprovalRequest:
    if call.resource is None:
        raise ValueError("Approval resource is missing")
    draft = ApprovalRequest(
        run_id=run.id,
        action=call.action,
        args=call.args.copy(),
        resource=call.resource,
        scope_hash=run.scope.hash,
        expires_at=utcnow() + timedelta(seconds=ttl_seconds),
        binding_hash="",
    )
    return draft.model_copy(update={"binding_hash": draft.computed_binding_hash()})


def revalidate_approval(
    run: Run,
    call: ToolCall,
    approval: ApprovalRequest | None,
    policy: PolicyEngine,
) -> str | None:
    now = utcnow()
    if now >= run.expires_at:
        return "RUN_EXPIRED"
    if approval is None:
        return "MISSING_APPROVAL"
    if approval.status is not ApprovalStatus.APPROVED:
        return "APPROVAL_NOT_GRANTED"
    if now >= approval.expires_at:
        return "APPROVAL_EXPIRED"
    if approval.run_id != run.id:
        return "APPROVAL_RUN_MISMATCH"
    if approval.action != call.action or approval.args != call.args:
        return "APPROVAL_ACTION_ARGUMENT_MISMATCH"
    if approval.resource != call.resource:
        return "APPROVAL_RESOURCE_MISMATCH"
    if approval.scope_hash != run.scope.hash:
        return "APPROVAL_SCOPE_MISMATCH"
    if approval.binding_hash != approval.computed_binding_hash():
        return "APPROVAL_BINDING_INVALID"
    if not run.user_authorization_valid:
        return "USER_AUTHORIZATION_REVOKED"
    if call.resource not in run.scope.allowed_services:
        return "RESOURCE_OUT_OF_SCOPE"
    result = policy.safe_evaluate(call, run.scope)
    if result.decision is not PolicyDecision.REQUIRE_APPROVAL:
        return f"POLICY_REVALIDATION_FAILED:{result.decision.value}"
    return None
