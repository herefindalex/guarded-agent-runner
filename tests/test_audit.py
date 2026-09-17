import pytest

from guarded_agent_runner.models import AuditEventType, RunStatus, ServiceName
from tests.conftest import advance_to_approval


@pytest.mark.asyncio
async def test_audit_events_are_complete_and_ordered(service):
    run, approval = await advance_to_approval(service)
    await service.approve(approval.id, "operator")
    result = await service.step(run.id)
    events = service.repository.list_audit(run.id)

    assert result.status is RunStatus.COMPLETED
    assert [event.event_type for event in events] == [
        AuditEventType.RUN_CREATED,
        AuditEventType.PLAN_GENERATED,
        AuditEventType.TOOL_REQUESTED,
        AuditEventType.TOOL_AUTO_AUTHORIZED,
        AuditEventType.TOOL_EXECUTION_STARTED,
        AuditEventType.TOOL_EXECUTION_SUCCEEDED,
        AuditEventType.TOOL_REQUESTED,
        AuditEventType.TOOL_AUTO_AUTHORIZED,
        AuditEventType.TOOL_EXECUTION_STARTED,
        AuditEventType.TOOL_EXECUTION_SUCCEEDED,
        AuditEventType.TOOL_REQUESTED,
        AuditEventType.APPROVAL_REQUESTED,
        AuditEventType.APPROVAL_GRANTED,
        AuditEventType.RESUME_REVALIDATION_STARTED,
        AuditEventType.RESUME_REVALIDATION_SUCCEEDED,
        AuditEventType.TOOL_EXECUTION_STARTED,
        AuditEventType.TOOL_EXECUTION_SUCCEEDED,
        AuditEventType.TOOL_REQUESTED,
        AuditEventType.TOOL_AUTO_AUTHORIZED,
        AuditEventType.TOOL_EXECUTION_STARTED,
        AuditEventType.TOOL_EXECUTION_SUCCEEDED,
        AuditEventType.RUN_COMPLETED,
    ]


@pytest.mark.asyncio
async def test_skipped_remediation_is_audited(service):
    run = service.create_run(
        "alex",
        "Diagnose Redis and restart it if necessary",
        target_service=ServiceName.REDIS,
    )
    result = await service.run_until_blocked(run.id)
    events = service.repository.list_audit(run.id)

    assert result.status is RunStatus.COMPLETED
    skipped = [event for event in events if event.event_type is AuditEventType.TOOL_SKIPPED]
    assert len(skipped) == 1
    assert skipped[0].metadata["decision"] == "NO_RESTART_NEEDED"
