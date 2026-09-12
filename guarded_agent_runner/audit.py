from typing import Any

from guarded_agent_runner.models import AuditEvent, AuditEventType


def audit_event(
    run_id: str,
    event_type: AuditEventType,
    *,
    actor: str,
    action: str | None = None,
    resource: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        run_id=run_id,
        actor=actor,
        event_type=event_type,
        action=action,
        resource=resource,
        metadata=metadata or {},
    )
