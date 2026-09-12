import pytest

from guarded_agent_runner.capability import ScopeExpansionError
from guarded_agent_runner.models import ApprovalMode, ApprovalRule, ServiceName


def test_scope_cannot_expand(service):
    run = service.create_run("alex", "Check nginx")
    draft = run.scope.model_copy(
        update={
            "allowed_services": ("nginx", "postgres"),
            "version": 2,
            "hash": "",
        }
    )
    run.scope = draft.model_copy(update={"hash": draft.computed_hash()})

    with pytest.raises(ScopeExpansionError):
        service.repository.save_run(run)


def test_scope_cannot_weaken_approval_requirement(service):
    run = service.create_run(
        "alex",
        "Check PostgreSQL",
        target_service=ServiceName.POSTGRESQL,
    )
    rules = tuple(
        ApprovalRule(
            action=rule.action,
            mode=ApprovalMode.AUTO if rule.action == "restart_service" else rule.mode,
        )
        for rule in run.scope.approval_policy
    )
    draft = run.scope.model_copy(update={"approval_policy": rules, "version": 2, "hash": ""})
    run.scope = draft.model_copy(update={"hash": draft.computed_hash()})

    with pytest.raises(ScopeExpansionError):
        service.repository.save_run(run)
