from datetime import timedelta

import pytest

from guarded_agent_runner.models import RunStatus, utcnow
from tests.conftest import advance_to_approval


@pytest.mark.asyncio
async def test_resume_revalidates_policy(service, infrastructure):
    run, approval = await advance_to_approval(service)
    await service.approve(approval.id, "operator")
    service.policy.force_failure = True

    result = await service.step(run.id)

    assert result.status is RunStatus.FAILED
    assert result.last_error == "POLICY_REVALIDATION_FAILED:DENY_INTERNAL_ERROR"
    assert all(action != "restart_service" for action, _ in infrastructure.executed_actions)


@pytest.mark.asyncio
async def test_resume_revalidates_run_expiry(service, infrastructure):
    run, approval = await advance_to_approval(service)
    await service.approve(approval.id, "operator")
    expired = service.get_run(run.id)
    expired.expires_at = utcnow() - timedelta(seconds=1)
    service.repository.save_run(expired)

    result = await service.step(run.id)

    assert result.status is RunStatus.EXPIRED
    assert result.last_error == "RUN_EXPIRED"
    assert all(action != "restart_service" for action, _ in infrastructure.executed_actions)


@pytest.mark.asyncio
async def test_resume_revalidates_user_authorization(service, infrastructure):
    run, approval = await advance_to_approval(service)
    await service.approve(approval.id, "operator")
    revoked = service.get_run(run.id)
    revoked.user_authorization_valid = False
    service.repository.save_run(revoked)

    result = await service.step(run.id)

    assert result.status is RunStatus.FAILED
    assert result.last_error == "USER_AUTHORIZATION_REVOKED"
    assert all(action != "restart_service" for action, _ in infrastructure.executed_actions)


@pytest.mark.asyncio
async def test_resume_revalidates_live_service_precondition(service, infrastructure):
    run, approval = await advance_to_approval(service)
    assert approval is not None
    await service.approve(approval.id, "operator")

    infrastructure.services["postgresql"]["status"] = "running"
    result = await service.step(run.id)

    assert result.status is RunStatus.STALE
    assert result.last_error == "STALE_PRECONDITION"
    assert result.pending_action is not None
    assert result.pending_action.status.value == "STALE"
    assert all(action != "restart_service" for action, _ in infrastructure.executed_actions)
