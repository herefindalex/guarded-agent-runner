from __future__ import annotations

import pytest

from guarded_agent_runner.executor.fake_infra import FakeInfrastructure
from guarded_agent_runner.models import ServiceName
from guarded_agent_runner.service import RunnerService
from guarded_agent_runner.storage.repository import Repository


@pytest.fixture
def repository(tmp_path):
    repo = Repository(f"sqlite:///{tmp_path / 'test.db'}")
    yield repo
    repo.close()


@pytest.fixture
def infrastructure():
    return FakeInfrastructure()


@pytest.fixture
def service(repository, infrastructure):
    return RunnerService(repository, infrastructure=infrastructure)


async def advance_to_approval(service: RunnerService):
    run = service.create_run(
        "alex",
        "Check PostgreSQL and restart it if necessary",
        target_service=ServiceName.POSTGRESQL,
    )
    await service.step(run.id)
    await service.step(run.id)
    run = await service.step(run.id)
    return run, service.repository.pending_approval_for_run(run.id)
