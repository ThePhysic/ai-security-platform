"""Real PostgreSQL handoff authority tests; source/scanner output stays inert."""

import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select

from ai_security_platform.api.app import create_app
from ai_security_platform.jobs.controller import LeaseLost
from ai_security_platform.scanners.registry import load_registry, registry_digest
from ai_security_platform.storage.launcher import dispatch, poll
from ai_security_platform.storage.models import AuditEvent, Finding, ScannerInvocation
from tests.postgres.test_intake import AUTH
from tests.postgres.test_intake import intake as intake_fixture
from tests.postgres.test_orchestration import execution as execution_fixture

execution = execution_fixture
intake = intake_fixture
pytestmark = pytest.mark.postgres
LAUNCHER_TOKEN = "launcher-synthetic-capability-" + "z" * 43
LAUNCHER_AUTH = {"Authorization": "Bearer " + LAUNCHER_TOKEN}


def test_distinct_capability_auth_no_origin_and_closed_default(pg_runtime):
    _, _, settings = pg_runtime
    with TestClient(create_app(settings), base_url="http://localhost:8000") as client:
        for header in (AUTH, {"Authorization": ""}, {}):
            assert (
                client.post(
                    "/internal/v1/launcher/next", json={"launcher_id": str(uuid4())}, headers=header
                ).status_code
                == 401
            )
    configured = settings.model_copy(update={"launcher_token": SecretStr(LAUNCHER_TOKEN)})
    with TestClient(create_app(configured), base_url="http://localhost:8000") as client:
        assert (
            client.get("/api/v1/projects/" + str(uuid4()), headers=LAUNCHER_AUTH).status_code == 401
        )
        assert (
            client.post(
                "/internal/v1/launcher/next",
                json={"launcher_id": str(uuid4())},
                headers=LAUNCHER_AUTH | {"Origin": "http://localhost:8000"},
            ).status_code
            == 403
        )


def test_lease_fenced_handoff_and_stale_staging(pg_runtime, pg_session, execution):
    controller, store, _ = execution
    settings = controller.settings.model_copy(update={"launcher_token": SecretStr(LAUNCHER_TOKEN)})
    app = create_app(settings)
    app.state.snapshot_store = store
    lease = controller.claim()
    identifier = dispatch(controller, lease)
    launcher_id = uuid4()
    with controller.factory() as session:
        invocation = poll(session, launcher_id)
    assert invocation["id"] == str(identifier)
    assert set(invocation) == {
        "id",
        "job_id",
        "generation",
        "lease_token",
        "snapshot_key",
        "manifest_digest",
        "profile",
        "registry_digest",
    }
    identity = {
        "launcher_id": str(launcher_id),
        "generation": lease.generation,
        "lease_token": str(lease.token),
    }
    with TestClient(app, base_url="http://localhost:8000") as client:
        url = "/internal/v1/launcher/" + str(identifier)
        assert client.post(url + "/check", json=identity, headers=LAUNCHER_AUTH).status_code == 200
        assert (
            client.post(
                url + "/check", json=identity | {"mount": "C:\\"}, headers=LAUNCHER_AUTH
            ).status_code
            == 422
        )
        assert (
            client.post(
                url + "/check", json=identity | {"lease_token": str(uuid4())}, headers=LAUNCHER_AUTH
            ).status_code
            == 409
        )
        time.sleep(0.45)
        before = pg_session.scalar(select(func.count()).select_from(AuditEvent))
        assert client.post(url + "/check", json=identity, headers=LAUNCHER_AUTH).status_code == 409
        response = client.post(
            url + "/result",
            json=identity | {"result": {"error_code": "execution_failed"}},
            headers=LAUNCHER_AUTH,
        )
        assert response.status_code == 409
        with pytest.raises(LeaseLost):
            dispatch(controller, lease)
        assert pg_session.scalar(select(func.count()).select_from(Finding)) == 0
        assert pg_session.scalar(select(func.count()).select_from(AuditEvent)) == before
        pg_session.expire_all()
        assert pg_session.get(ScannerInvocation, identifier).result is None


def test_live_capability_registry_and_no_generic_proxy(pg_runtime, pg_session):
    _, _, settings = pg_runtime
    settings = settings.model_copy(update={"launcher_token": SecretStr(LAUNCHER_TOKEN)})
    registry = load_registry(settings.scanner_registry)
    body = {
        "launcher_id": str(uuid4()),
        "registry_digest": registry_digest(registry),
        "gate_digest": "a" * 64,
    }
    with TestClient(create_app(settings), base_url="http://localhost:8000") as client:
        assert (
            client.post("/internal/v1/launcher/hello", headers=AUTH, json=body).status_code == 401
        )
        assert (
            client.post(
                "/internal/v1/launcher/hello",
                headers=LAUNCHER_AUTH,
                json=body | {"registry_digest": "b" * 64},
            ).status_code
            == 409
        )
        assert (
            client.post("/internal/v1/launcher/hello", headers=LAUNCHER_AUTH, json=body).status_code
            == 200
        )
        assert (
            client.post(
                "/internal/v1/launcher/next",
                headers=LAUNCHER_AUTH,
                json={
                    "launcher_id": body["launcher_id"],
                    "command": "docker run --privileged",
                },
            ).status_code
            == 422
        )
