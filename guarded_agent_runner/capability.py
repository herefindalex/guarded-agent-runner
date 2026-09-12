from __future__ import annotations

from guarded_agent_runner.models import ApprovalMode, ApprovalRule, CapabilityScope, ServiceName

DEFAULT_ACTIONS = ("read_log", "restart_service", "service_status")


class ScopeExpansionError(ValueError):
    """Raised when a persisted run attempts to gain capability."""


def compile_scope(service: ServiceName = ServiceName.NGINX) -> CapabilityScope:
    restart_mode = ApprovalMode.AUTO if service is ServiceName.NGINX else ApprovalMode.REQUIRED
    rules = (
        ApprovalRule(action="read_log", mode=ApprovalMode.AUTO),
        ApprovalRule(action="restart_service", mode=restart_mode),
        ApprovalRule(action="service_status", mode=ApprovalMode.AUTO),
    )
    draft = CapabilityScope(
        allowed_services=(service.value,),
        allowed_actions=DEFAULT_ACTIONS,
        approval_policy=rules,
        version=1,
        hash="",
    )
    return draft.model_copy(update={"hash": draft.computed_hash()})


def assert_scope_integrity(scope: CapabilityScope) -> None:
    if not scope.hash or scope.hash != scope.computed_hash():
        raise ValueError("Capability scope hash is missing or invalid")


def assert_no_scope_expansion(new_scope: CapabilityScope, old_scope: CapabilityScope) -> None:
    assert_scope_integrity(new_scope)
    if not new_scope.is_subset_of(old_scope):
        raise ScopeExpansionError("Capability scope may shrink but must never expand")
