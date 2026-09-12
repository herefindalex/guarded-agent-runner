from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import timedelta

from guarded_agent_runner.approval import create_approval, revalidate_approval
from guarded_agent_runner.audit import audit_event
from guarded_agent_runner.capability import compile_scope
from guarded_agent_runner.executor.fake_infra import FakeInfrastructure
from guarded_agent_runner.executor.guarded_executor import GuardedExecutor
from guarded_agent_runner.models import (
    ActionStatus,
    ApprovalRequest,
    ApprovalStatus,
    AuditEventType,
    ExecutionToken,
    PlanPreset,
    PolicyDecision,
    Run,
    RunStatus,
    ServiceName,
    utcnow,
)
from guarded_agent_runner.planner.deterministic_planner import DeterministicPlanner
from guarded_agent_runner.policy.policy_engine import PolicyEngine
from guarded_agent_runner.run import transition_run
from guarded_agent_runner.storage.repository import Repository


class RunnerError(RuntimeError):
    status_code = 400


class NotFoundError(RunnerError):
    status_code = 404


class ConflictError(RunnerError):
    status_code = 409


class RunnerService:
    def __init__(
        self,
        repository: Repository,
        *,
        planner: DeterministicPlanner | None = None,
        policy: PolicyEngine | None = None,
        infrastructure: FakeInfrastructure | None = None,
        run_ttl_seconds: float = 900,
        approval_ttl_seconds: float = 300,
        execution_timeout_seconds: float = 2,
    ) -> None:
        self.repository = repository
        self.planner = planner or DeterministicPlanner()
        self.policy = policy or PolicyEngine()
        self.infrastructure = infrastructure or FakeInfrastructure()
        self.executor = GuardedExecutor(self.infrastructure, timeout_seconds=execution_timeout_seconds)
        self.run_ttl_seconds = run_ttl_seconds
        self.approval_ttl_seconds = approval_ttl_seconds
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    def create_run(
        self,
        user_id: str,
        request: str,
        workflow: PlanPreset = PlanPreset.DIAGNOSE_AND_RESTART,
        target_service: ServiceName = ServiceName.NGINX,
    ) -> Run:
        created_at = utcnow()
        run = Run(
            user_id=user_id,
            request=request,
            workflow=workflow,
            target_service=target_service,
            scope=compile_scope(target_service),
            created_at=created_at,
            expires_at=created_at + timedelta(seconds=self.run_ttl_seconds),
        )
        self.repository.save_run(run)
        self._audit(run, AuditEventType.RUN_CREATED, actor=user_id)

        # The planner receives request text only. It never sees credentials or authorization objects.
        run.plan = self.planner.plan(request, workflow, target_service)
        transition_run(run, RunStatus.PLANNED)
        self.repository.save_run(run)
        self._audit(
            run,
            AuditEventType.PLAN_GENERATED,
            actor="planner",
            metadata={
                "action_count": len(run.plan),
                "workflow": workflow.value,
                "target_service": target_service.value,
            },
        )
        return run

    def get_run(self, run_id: str) -> Run:
        run = self.repository.get_run(run_id)
        if run is None:
            raise NotFoundError(f"Run not found: {run_id}")
        return run

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        approval = self.repository.get_approval(approval_id)
        if approval is None:
            raise NotFoundError(f"Approval not found: {approval_id}")
        return approval

    async def step(self, run_id: str) -> Run:
        async with self._locks[run_id]:
            run = self.get_run(run_id)
            if run.status in {
                RunStatus.REJECTED,
                RunStatus.COMPLETED,
                RunStatus.FAILED,
                RunStatus.EXPIRED,
                RunStatus.CANCELLED,
            }:
                raise ConflictError(f"Run is terminal: {run.status.value}")
            if run.status is RunStatus.WAITING_APPROVAL:
                raise ConflictError("Run is waiting for a human approval decision")
            if run.status is RunStatus.PLANNED:
                if utcnow() >= run.expires_at:
                    return self._fail_expired(run)
                transition_run(run, RunStatus.RUNNING)
                self.repository.save_run(run)
            if run.status is RunStatus.APPROVED:
                return await self._resume_after_approval(run)
            if utcnow() >= run.expires_at:
                return self._fail_expired(run)
            return await self._advance(run)

    async def run_until_blocked(self, run_id: str) -> Run:
        """Advance automatic actions and stop at approval or a terminal state."""
        run = self.get_run(run_id)
        max_advances = len(run.plan) + 1
        for _ in range(max_advances):
            if run.status in {
                RunStatus.WAITING_APPROVAL,
                RunStatus.REJECTED,
                RunStatus.COMPLETED,
                RunStatus.FAILED,
                RunStatus.EXPIRED,
                RunStatus.CANCELLED,
            }:
                return run
            run = await self.step(run_id)
        raise ConflictError("Run did not reach an approval gate or terminal state")

    async def _advance(self, run: Run) -> Run:
        call = run.pending_action
        if call is None:
            transition_run(run, RunStatus.COMPLETED)
            self.repository.save_run(run)
            self._audit(run, AuditEventType.RUN_COMPLETED, actor="runner")
            return run

        self._audit_call(run, AuditEventType.TOOL_REQUESTED, call, actor="planner")

        skip_result = self._conditional_remediation_skip(run, call)
        if skip_result is not None:
            call.status = ActionStatus.SKIPPED
            call.result = skip_result
            run.current_step += 1
            self._audit_call(
                run,
                AuditEventType.TOOL_SKIPPED,
                call,
                actor="runner",
                metadata=skip_result,
            )
            if run.pending_action is None:
                transition_run(run, RunStatus.COMPLETED)
                self.repository.save_run(run)
                self._audit(run, AuditEventType.RUN_COMPLETED, actor="runner")
            else:
                self.repository.save_run(run)
            return run

        result = self.policy.safe_evaluate(call, run.scope)
        if result.decision not in {PolicyDecision.ALLOW_AUTO, PolicyDecision.REQUIRE_APPROVAL}:
            call.status = ActionStatus.DENIED
            call.failure_reason = result.decision.value
            run.last_error = result.reason
            self._audit_call(
                run,
                AuditEventType.TOOL_DENIED,
                call,
                actor="policy",
                metadata={"decision": result.decision.value, "reason": result.reason},
            )
            transition_run(run, RunStatus.FAILED)
            self.repository.save_run(run)
            self._audit(
                run,
                AuditEventType.RUN_FAILED,
                actor="runner",
                metadata={"reason": result.decision.value},
            )
            return run

        if result.decision is PolicyDecision.REQUIRE_APPROVAL:
            approval = create_approval(run, call, self.approval_ttl_seconds)
            if approval.expires_at > run.expires_at:
                approval = approval.model_copy(update={"expires_at": run.expires_at})
                approval.binding_hash = approval.computed_binding_hash()
            self.repository.save_approval(approval)
            call.status = ActionStatus.WAITING_APPROVAL
            transition_run(run, RunStatus.WAITING_APPROVAL)
            self.repository.save_run(run)
            self._audit_call(
                run,
                AuditEventType.APPROVAL_REQUESTED,
                call,
                actor="policy",
                metadata={"approval_id": approval.id, "expires_at": approval.expires_at.isoformat()},
            )
            return run

        self._audit_call(
            run,
            AuditEventType.TOOL_AUTO_AUTHORIZED,
            call,
            actor="policy",
            metadata={"decision": result.decision.value},
        )
        return await self._execute(run)

    def _conditional_remediation_skip(self, run: Run, call) -> dict | None:
        """Return an explainable skip result when diagnostics show no restart is needed."""
        if call.action != "restart_service" or call.purpose != "remediate_if_needed":
            return None

        observed_status = None
        evidence_lines: list[str] = []
        for prior in run.plan[: run.current_step]:
            if not isinstance(prior.result, dict):
                continue
            if prior.purpose == "diagnose_current_state":
                status = prior.result.get("status")
                if isinstance(status, str):
                    observed_status = status.lower()
            if prior.purpose == "inspect_recent_evidence":
                lines = prior.result.get("lines", [])
                if isinstance(lines, list):
                    evidence_lines.extend(str(line) for line in lines)

        failure_terms = ("failed", "error", "degraded", "restarting", "unavailable")
        unhealthy_evidence = any(
            term in line.lower() for line in evidence_lines for term in failure_terms
        )
        restart_needed = observed_status != "running" or unhealthy_evidence
        if restart_needed:
            return None

        return {
            "executed": False,
            "decision": "NO_RESTART_NEEDED",
            "observed_status": observed_status,
            "reason": "Service is healthy; remediation was skipped.",
        }

    async def _resume_after_approval(self, run: Run) -> Run:
        call = run.pending_action
        approval = self.repository.latest_approval_for_run(run.id)
        self._audit_call(
            run,
            AuditEventType.RESUME_REVALIDATION_STARTED,
            call,
            actor="runner",
            metadata={"approval_id": approval.id if approval else None},
        )
        if call is None:
            return self._fail_resume(run, call, "MISSING_PENDING_ACTION")
        failure = revalidate_approval(run, call, approval, self.policy)
        if failure:
            return self._fail_resume(run, call, failure)
        call.status = ActionStatus.APPROVED
        transition_run(run, RunStatus.RUNNING)
        self.repository.save_run(run)
        run = await self._execute(run)

        # Approval authorizes only the exact pending action. Once it has executed,
        # continue ordinary policy evaluation for any remaining verification steps.
        for _ in range(len(run.plan) + 1):
            if run.status in {
                RunStatus.WAITING_APPROVAL,
                RunStatus.REJECTED,
                RunStatus.COMPLETED,
                RunStatus.FAILED,
                RunStatus.EXPIRED,
                RunStatus.CANCELLED,
            }:
                return run
            run = await self._advance(run)
        raise ConflictError("Approved run did not reach a terminal state or approval gate")

    async def _execute(self, run: Run) -> Run:
        call = run.pending_action
        if call is None or call.resource is None:
            return self._fail_resume(run, call, "MALFORMED_TOOL_CALL")
        call.status = ActionStatus.RUNNING
        self.repository.save_run(run)
        self._audit_call(run, AuditEventType.TOOL_EXECUTION_STARTED, call, actor="executor")
        token = ExecutionToken(
            run_id=run.id,
            action=call.action,
            resource=call.resource,
            expires_at=utcnow() + timedelta(seconds=self.executor.timeout_seconds + 1),
        )
        try:
            result = await self.executor.execute(run.id, call, token)
        except Exception as exc:
            call.status = ActionStatus.FAILED
            call.failure_reason = type(exc).__name__
            run.last_error = str(exc)
            self._audit_call(
                run,
                AuditEventType.TOOL_EXECUTION_FAILED,
                call,
                actor="executor",
                metadata={"error_type": type(exc).__name__, "reason": str(exc)},
            )
            transition_run(run, RunStatus.FAILED)
            self.repository.save_run(run)
            self._audit(
                run,
                AuditEventType.RUN_FAILED,
                actor="runner",
                metadata={"reason": type(exc).__name__},
            )
            return run

        call.status = ActionStatus.SUCCEEDED
        call.result = result
        run.current_step += 1
        self._audit_call(run, AuditEventType.TOOL_EXECUTION_SUCCEEDED, call, actor="executor")
        if run.pending_action is None:
            transition_run(run, RunStatus.COMPLETED)
            self.repository.save_run(run)
            self._audit(run, AuditEventType.RUN_COMPLETED, actor="runner")
        else:
            self.repository.save_run(run)
        return run

    async def approve(self, approval_id: str, actor: str) -> Run:
        approval = self.get_approval(approval_id)
        async with self._locks[approval.run_id]:
            approval = self.get_approval(approval_id)
            run = self.get_run(approval.run_id)
            if approval.status is not ApprovalStatus.PENDING:
                raise ConflictError(f"Approval is already {approval.status.value}")
            if run.status is not RunStatus.WAITING_APPROVAL:
                raise ConflictError(f"Run is not waiting for approval: {run.status.value}")
            if utcnow() >= approval.expires_at:
                approval.status = ApprovalStatus.EXPIRED
                approval.decided_by = actor
                self.repository.save_approval(approval)
                self._audit(
                    run,
                    AuditEventType.APPROVAL_REJECTED,
                    actor=actor,
                    action=approval.action,
                    resource=approval.resource,
                    metadata={"approval_id": approval.id, "reason": "APPROVAL_EXPIRED"},
                )
                transition_run(run, RunStatus.FAILED)
                run.last_error = "APPROVAL_EXPIRED"
                self.repository.save_run(run)
                self._audit(
                    run,
                    AuditEventType.RUN_FAILED,
                    actor="runner",
                    metadata={"reason": "APPROVAL_EXPIRED"},
                )
                return run
            approval.status = ApprovalStatus.APPROVED
            approval.decided_by = actor
            self.repository.save_approval(approval)
            pending = run.pending_action
            if pending:
                pending.status = ActionStatus.APPROVED
            transition_run(run, RunStatus.APPROVED)
            self.repository.save_run(run)
            self._audit(
                run,
                AuditEventType.APPROVAL_GRANTED,
                actor=actor,
                action=approval.action,
                resource=approval.resource,
                metadata={"approval_id": approval.id, "binding_hash": approval.binding_hash},
            )
            return run

    async def reject(self, approval_id: str, actor: str) -> Run:
        approval = self.get_approval(approval_id)
        async with self._locks[approval.run_id]:
            approval = self.get_approval(approval_id)
            run = self.get_run(approval.run_id)
            if approval.status is not ApprovalStatus.PENDING:
                raise ConflictError(f"Approval is already {approval.status.value}")
            if run.status is not RunStatus.WAITING_APPROVAL:
                raise ConflictError(f"Run is not waiting for approval: {run.status.value}")
            approval.status = ApprovalStatus.REJECTED
            approval.decided_by = actor
            self.repository.save_approval(approval)
            if run.pending_action:
                run.pending_action.status = ActionStatus.DENIED
                run.pending_action.failure_reason = "APPROVAL_REJECTED"
            transition_run(run, RunStatus.REJECTED)
            self.repository.save_run(run)
            self._audit(
                run,
                AuditEventType.APPROVAL_REJECTED,
                actor=actor,
                action=approval.action,
                resource=approval.resource,
                metadata={"approval_id": approval.id},
            )
            return run

    def view(self, run: Run) -> dict:
        approval = self.repository.latest_approval_for_run(run.id)
        return {
            **run.model_dump(mode="json"),
            "pending_approval": approval.model_dump(mode="json") if approval else None,
        }

    def _fail_expired(self, run: Run) -> Run:
        run.last_error = "RUN_EXPIRED"
        transition_run(run, RunStatus.EXPIRED)
        self.repository.save_run(run)
        self._audit(run, AuditEventType.RUN_FAILED, actor="runner", metadata={"reason": "RUN_EXPIRED"})
        return run

    def _fail_resume(self, run: Run, call, reason: str) -> Run:
        if call is not None:
            call.status = ActionStatus.FAILED
            call.failure_reason = reason
        run.last_error = reason
        self._audit_call(
            run,
            AuditEventType.RESUME_REVALIDATION_FAILED,
            call,
            actor="runner",
            metadata={"reason": reason},
        )
        target = RunStatus.EXPIRED if reason == "RUN_EXPIRED" else RunStatus.FAILED
        transition_run(run, target)
        self.repository.save_run(run)
        self._audit(run, AuditEventType.RUN_FAILED, actor="runner", metadata={"reason": reason})
        return run

    def _audit(
        self,
        run: Run,
        event_type: AuditEventType,
        *,
        actor: str,
        action: str | None = None,
        resource: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        self.repository.append_audit(
            audit_event(
                run.id,
                event_type,
                actor=actor,
                action=action,
                resource=resource,
                metadata=metadata,
            )
        )

    def _audit_call(
        self,
        run: Run,
        event_type: AuditEventType,
        call,
        *,
        actor: str,
        metadata: dict | None = None,
    ) -> None:
        self._audit(
            run,
            event_type,
            actor=actor,
            action=call.action if call else None,
            resource=call.resource if call else None,
            metadata=metadata,
        )
