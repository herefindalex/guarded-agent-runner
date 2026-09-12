from datetime import timedelta

import pytest

from guarded_agent_runner.models import ApprovalStatus, RunStatus, utcnow
from tests.conftest import advance_to_approval


@pytest.mark.asyncio
async def test_approval_is_bound_to_action_args_and_scope(service, infrastructure):
    run, approval = await advance_to_approval(service)
    assert approval is not None
    await service.approve(approval.id, "operator")

    tampered = service.get_run(run.id)
    tampered.pending_action.args = {"service": "mysql"}
    service.repository.save_run(tampered)
    result = await service.step(run.id)

    assert result.status is RunStatus.FAILED
    assert result.last_error == "APPROVAL_ACTION_ARGUMENT_MISMATCH"
    assert all(action != "restart_service" for action, _ in infrastructure.executed_actions)


@pytest.mark.asyncio
async def test_approval_expiry_blocks_execution(service, infrastructure):
    run, approval = await advance_to_approval(service)
    assert approval is not None
    approval.expires_at = utcnow() - timedelta(seconds=1)
    approval.binding_hash = approval.computed_binding_hash()
    service.repository.save_approval(approval)

    result = await service.approve(approval.id, "operator")
    stored = service.get_approval(approval.id)
    assert result.status is RunStatus.FAILED
    assert stored.status is ApprovalStatus.EXPIRED
    assert all(action != "restart_service" for action, _ in infrastructure.executed_actions)


@pytest.mark.asyncio
async def test_rejected_approval_is_terminal(service, infrastructure):
    run, approval = await advance_to_approval(service)
    result = await service.reject(approval.id, "operator")

    assert result.status is RunStatus.REJECTED
    assert all(action != "restart_service" for action, _ in infrastructure.executed_actions)
