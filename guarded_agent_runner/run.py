from guarded_agent_runner.models import Run, RunStatus


class InvalidRunTransition(ValueError):
    pass


ALLOWED_TRANSITIONS: dict[RunStatus, set[RunStatus]] = {
    RunStatus.CREATED: {RunStatus.PLANNED, RunStatus.FAILED, RunStatus.CANCELLED},
    RunStatus.PLANNED: {RunStatus.RUNNING, RunStatus.FAILED, RunStatus.EXPIRED, RunStatus.CANCELLED},
    RunStatus.RUNNING: {
        RunStatus.WAITING_APPROVAL,
        RunStatus.COMPLETED,
        RunStatus.FAILED,
        RunStatus.EXPIRED,
        RunStatus.CANCELLED,
    },
    RunStatus.WAITING_APPROVAL: {
        RunStatus.APPROVED,
        RunStatus.REJECTED,
        RunStatus.FAILED,
        RunStatus.EXPIRED,
        RunStatus.CANCELLED,
    },
    RunStatus.APPROVED: {
        RunStatus.RUNNING,
        RunStatus.FAILED,
        RunStatus.STALE,
        RunStatus.EXPIRED,
        RunStatus.CANCELLED,
    },
    RunStatus.REJECTED: set(),
    RunStatus.COMPLETED: set(),
    RunStatus.FAILED: set(),
    RunStatus.STALE: set(),
    RunStatus.EXPIRED: set(),
    RunStatus.CANCELLED: set(),
}


def transition_run(run: Run, target: RunStatus) -> None:
    if target not in ALLOWED_TRANSITIONS[run.status]:
        raise InvalidRunTransition(f"Invalid run transition: {run.status} -> {target}")
    run.status = target
    run.version += 1
