import pytest
from httpx2 import ASGITransport, AsyncClient

from guarded_agent_runner.main import create_app
from guarded_agent_runner.service import RunnerService
from guarded_agent_runner.storage.repository import Repository


@pytest.mark.asyncio
async def test_health_and_run_endpoints(tmp_path):
    repository = Repository(f"sqlite:///{tmp_path / 'api.db'}")
    app = create_app(repository, RunnerService(repository))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/health")).json() == {"status": "ok"}
        created = await client.post(
            "/runs",
            json={"user_id": "alex", "request": "Check nginx and restart if necessary"},
        )
        assert created.status_code == 200
        run = created.json()
        assert run["status"] == "PLANNED"
        assert run["scope"]["allowed_services"] == ["nginx"]

        stepped = await client.post(f"/runs/{run['id']}/step")
        assert stepped.status_code == 200
        assert stepped.json()["plan"][0]["status"] == "SUCCEEDED"

        audit = await client.get(f"/runs/{run['id']}/audit")
        assert audit.status_code == 200
        assert audit.json()[0]["event_type"] == "RUN_CREATED"
    repository.close()


@pytest.mark.asyncio
async def test_selected_service_is_the_only_service_in_scope(tmp_path):
    repository = Repository(f"sqlite:///{tmp_path / 'service-selection.db'}")
    app = create_app(repository, RunnerService(repository))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/runs",
            json={
                "user_id": "alex",
                "request": "Check PostgreSQL",
                "workflow": "status_only",
                "target_service": "postgresql",
            },
        )
        run = response.json()
        assert response.status_code == 200
        assert run["scope"]["allowed_services"] == ["postgresql"]
        assert run["plan"][0]["args"] == {"service": "postgresql"}
    repository.close()
