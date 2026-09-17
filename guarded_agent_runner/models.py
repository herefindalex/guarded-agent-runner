from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class RunStatus(StrEnum):
    CREATED = "CREATED"
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STALE = "STALE"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class ActionStatus(StrEnum):
    PENDING = "PENDING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    APPROVED = "APPROVED"
    SKIPPED = "SKIPPED"
    DENIED = "DENIED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    STALE = "STALE"


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalMode(StrEnum):
    AUTO = "auto"
    REQUIRED = "required"


class PlanPreset(StrEnum):
    STATUS_ONLY = "status_only"
    LOGS_ONLY = "logs_only"
    STATUS_AND_LOGS = "status_and_logs"
    DIAGNOSE_AND_RESTART = "diagnose_and_restart"


class ServiceName(StrEnum):
    SERVICE_A = "service-a"
    NGINX = "nginx"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    REDIS = "redis"


class PolicyDecision(StrEnum):
    ALLOW_AUTO = "ALLOW_AUTO"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY_OUT_OF_SCOPE = "DENY_OUT_OF_SCOPE"
    DENY_UNKNOWN_ACTION = "DENY_UNKNOWN_ACTION"
    DENY_INVALID_ARGUMENTS = "DENY_INVALID_ARGUMENTS"
    DENY_INVALID_SCOPE = "DENY_INVALID_SCOPE"
    DENY_INTERNAL_ERROR = "DENY_INTERNAL_ERROR"


class AuditEventType(StrEnum):
    RUN_CREATED = "RUN_CREATED"
    PLAN_GENERATED = "PLAN_GENERATED"
    TOOL_REQUESTED = "TOOL_REQUESTED"
    TOOL_AUTO_AUTHORIZED = "TOOL_AUTO_AUTHORIZED"
    TOOL_SKIPPED = "TOOL_SKIPPED"
    TOOL_DENIED = "TOOL_DENIED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    RESUME_REVALIDATION_STARTED = "RESUME_REVALIDATION_STARTED"
    RESUME_REVALIDATION_SUCCEEDED = "RESUME_REVALIDATION_SUCCEEDED"
    RESUME_REVALIDATION_FAILED = "RESUME_REVALIDATION_FAILED"
    TOOL_EXECUTION_STARTED = "TOOL_EXECUTION_STARTED"
    TOOL_EXECUTION_SUCCEEDED = "TOOL_EXECUTION_SUCCEEDED"
    TOOL_EXECUTION_FAILED = "TOOL_EXECUTION_FAILED"
    RUN_COMPLETED = "RUN_COMPLETED"
    RUN_FAILED = "RUN_FAILED"


class ApprovalRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    action: str
    mode: ApprovalMode


class CapabilityScope(BaseModel):
    model_config = ConfigDict(frozen=True)

    allowed_services: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    approval_policy: tuple[ApprovalRule, ...]
    version: int = 1
    hash: str

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "allowed_actions": sorted(self.allowed_actions),
            "allowed_services": sorted(self.allowed_services),
            "approval_policy": {
                rule.action: rule.mode.value
                for rule in sorted(self.approval_policy, key=lambda item: item.action)
            },
            "version": self.version,
        }

    def computed_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.canonical_payload()).encode()).hexdigest()

    def mode_for(self, action: str) -> ApprovalMode | None:
        return next((rule.mode for rule in self.approval_policy if rule.action == action), None)

    def is_subset_of(self, previous: CapabilityScope) -> bool:
        if self.version < previous.version:
            return False
        if not set(self.allowed_services).issubset(previous.allowed_services):
            return False
        if not set(self.allowed_actions).issubset(previous.allowed_actions):
            return False
        strength = {ApprovalMode.AUTO: 0, ApprovalMode.REQUIRED: 1}
        for action in self.allowed_actions:
            old_mode = previous.mode_for(action)
            new_mode = self.mode_for(action)
            if old_mode is None or new_mode is None or strength[new_mode] < strength[old_mode]:
                return False
        return True


class ToolCall(BaseModel):
    id: str = Field(default_factory=lambda: new_id("call"))
    action: str
    args: dict[str, Any]
    purpose: str | None = None
    status: ActionStatus = ActionStatus.PENDING
    result: Any | None = None
    failure_reason: str | None = None

    @property
    def resource(self) -> str | None:
        service = self.args.get("service")
        return service if isinstance(service, str) else None


class Run(BaseModel):
    id: str = Field(default_factory=lambda: new_id("run"))
    user_id: str
    request: str
    workflow: PlanPreset = PlanPreset.DIAGNOSE_AND_RESTART
    target_service: ServiceName = ServiceName.NGINX
    status: RunStatus = RunStatus.CREATED
    scope: CapabilityScope
    plan: list[ToolCall] = Field(default_factory=list)
    current_step: int = 0
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    user_authorization_valid: bool = True
    last_error: str | None = None
    version: int = 1

    @property
    def pending_action(self) -> ToolCall | None:
        if self.current_step >= len(self.plan):
            return None
        return self.plan[self.current_step]


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: new_id("approval"))
    run_id: str
    action: str
    args: dict[str, Any]
    resource: str
    scope_hash: str
    precondition: dict[str, Any] | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    binding_hash: str
    decided_by: str | None = None

    def binding_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "action": self.action,
            "args": self.args,
            "resource": self.resource,
            "scope_hash": self.scope_hash,
            "precondition": self.precondition,
            "expires_at": self.expires_at.isoformat(),
        }

    def computed_binding_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.binding_payload()).encode()).hexdigest()


class ExecutionToken(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    action: str
    resource: str
    expires_at: datetime
    nonce: str = Field(default_factory=lambda: uuid4().hex)


class AuditEvent(BaseModel):
    id: int | None = None
    run_id: str
    actor: str
    event_type: AuditEventType
    action: str | None = None
    resource: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)


class PolicyResult(BaseModel):
    decision: PolicyDecision
    reason: str
