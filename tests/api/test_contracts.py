import asyncio
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.exc import OperationalError

from ai_security_platform.storage import repositories
from tests.conftest import SENSITIVE, TOKEN

pytestmark = pytest.mark.api


def test_public_liveness(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["x-request-id"]
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer invalid"}, {"Authorization": "Basic invalid"}]
)
def test_authentication(client, headers):
    response = client.get(f"/api/v1/projects/{uuid4()}", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert set(response.json()) == {"code", "message", "request_id", "retryable", "details"}


@pytest.mark.parametrize("origin", ["null", "https://attacker.invalid", "http://localhost:8000/"])
def test_denied_origins(client, auth, origin):
    response = client.get("/health", headers=auth | {"Origin": origin})
    assert response.status_code == 403
    assert "access-control-allow-origin" not in response.headers


def test_exact_host_and_origin(client, auth, monkeypatch):
    monkeypatch.setattr(repositories, "get_project", lambda *args: None)
    assert client.get("/health", headers={"Host": "attacker.invalid"}).status_code == 400
    assert client.get("/health", headers={"Host": "localhost.evil:8000"}).status_code == 400
    response = client.get(f"/api/v1/projects/{uuid4()}", headers=auth)
    assert response.status_code == 404
    response = client.get("/health", headers={"Origin": "http://localhost:8000"})
    assert response.headers["access-control-allow-origin"] == "http://localhost:8000"
    assert "access-control-allow-credentials" not in response.headers


def test_preflight(client):
    headers = {
        "Origin": "http://localhost:8000",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization, Content-Type",
    }
    assert client.options("/api/v1/projects", headers=headers).status_code == 204
    assert (
        client.options(
            "/health", headers=headers | {"Access-Control-Request-Method": "DELETE"}
        ).status_code
        == 403
    )
    assert (
        client.options(
            "/health", headers=headers | {"Access-Control-Request-Headers": "X-Forbidden"}
        ).status_code
        == 403
    )


def test_project_contracts(client, auth, monkeypatch):
    project = SimpleNamespace(id=uuid4(), name="Example", created_at=datetime.now(UTC))
    seen = []

    def create(session, name, request_id):
        seen.append((name, request_id))
        return project

    monkeypatch.setattr(repositories, "create_project", create)
    monkeypatch.setattr(repositories, "get_project", lambda *args: project)
    response = client.post(
        "/api/v1/projects",
        json={"name": " Example "},
        headers=auth | {"X-Request-ID": "safe_request-1"},
    )
    assert response.status_code == 201
    assert seen == [("Example", "safe_request-1")]
    assert client.get(f"/api/v1/projects/{project.id}", headers=auth).json() == response.json()


def test_scan_metadata_contract(client, auth, monkeypatch):
    import ai_security_platform.api.routes.scan_runs as routes

    scan = SimpleNamespace(
        id=uuid4(),
        project_id=uuid4(),
        snapshot_id=uuid4(),
        profile_id="test-metadata",
        profile_digest="a" * 64,
        status="queued",
        created_at=datetime.now(UTC),
        started_at=None,
        completed_at=None,
    )
    monkeypatch.setattr(routes, "get_scan", lambda *args: scan)
    response = client.get(f"/api/v1/scan-runs/{scan.id}", headers=auth)
    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert "findings" not in response.json()
    monkeypatch.setattr(routes, "get_scan", lambda *args: None)
    assert client.get(f"/api/v1/scan-runs/{scan.id}", headers=auth).status_code == 404


@pytest.mark.parametrize(
    "path",
    ["/api/v1/scan-runs", "/api/v1/source-snapshots", "/api/v1/findings", "/docs", "/openapi.json"],
)
def test_future_routes_are_absent(client, auth, path):
    assert client.post(path, headers=auth, json={}).status_code == 404


def test_openapi_is_only_phase1(app):
    assert set(app.openapi()["paths"]) == {
        "/health",
        "/ready",
        "/api/v1/projects",
        "/api/v1/projects/{project_id}",
        "/api/v1/scan-runs/{scan_id}",
    }


def test_validation_limits_and_sensitive_errors(client, auth, logs):
    for payload in [
        {"name": SENSITIVE, SENSITIVE: SENSITIVE},
        {"name": "x" * 201},
        {"name": "\x00"},
    ]:
        response = client.post("/api/v1/projects", headers=auth, json=payload)
        assert response.status_code == 422
        assert SENSITIVE not in response.text
    response = client.get(
        f"/api/v1/projects/{SENSITIVE}?token={SENSITIVE}",
        headers=auth | {"X-Request-ID": SENSITIVE + "\x01"},
    )
    assert response.status_code == 422
    assert SENSITIVE not in response.text
    assert SENSITIVE not in logs.getvalue()
    assert TOKEN not in logs.getvalue()
    assert client.post("/api/v1/projects", headers=auth, content=b"x" * 16385).status_code == 413
    assert client.get("/health", headers={"Authorization": "x" * 4097}).status_code == 413


def test_unknown_exception_is_sanitized(app, client, auth, logs):
    def fail():
        raise RuntimeError(SENSITIVE)

    app.add_api_route("/test-failure", fail)
    response = client.get("/test-failure", headers=auth)
    assert response.status_code == 500
    assert SENSITIVE not in response.text + logs.getvalue()


def test_dependency_unavailable_and_schema_mismatch(app, client, logs):
    engine = MagicMock()
    engine.connect.side_effect = OperationalError("synthetic", {}, Exception(SENSITIVE))
    app.state.engine = engine
    assert client.get("/ready").status_code == 503
    assert client.get("/health").status_code == 200
    assert SENSITIVE not in logs.getvalue()
    engine.connect.side_effect = None
    result = engine.connect.return_value.__enter__.return_value.execute.return_value
    result.scalars.return_value = ["wrong_revision"]
    assert client.get("/ready").json()["code"] == "schema_unavailable"
    result.scalars.return_value = ["0001_foundation"]
    assert client.get("/ready").status_code == 200


def raw_request(app, chunks, *, content_length=None):
    async def run():
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "scheme": "http",
            "method": "POST",
            "path": "/api/v1/projects",
            "raw_path": b"/api/v1/projects",
            "query_string": b"",
            "root_path": "",
            "server": ("localhost", 8000),
            "client": ("127.0.0.1", 1),
            "headers": [
                (b"host", b"localhost:8000"),
                (b"authorization", f"Bearer {TOKEN}".encode()),
            ],
        }
        if content_length is not None:
            scope["headers"].append((b"content-length", content_length))
        messages = iter(chunks)
        sent = []

        async def receive():
            return next(messages)

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        return sent

    return asyncio.run(run())


def test_streamed_size_limit_without_length(app):
    sent = raw_request(
        app,
        [
            {"type": "http.request", "body": b"x" * 10000, "more_body": True},
            {"type": "http.request", "body": b"x" * 10000, "more_body": False},
        ],
    )
    assert sent[0]["status"] == 413
    assert json.loads(sent[1]["body"])["code"] == "body_too_large"


def test_ambiguous_and_invalid_length(app):
    sent = raw_request(app, [], content_length=b"-1")
    assert sent[0]["status"] == 400


def test_log_is_structured(client, logs):
    client.get("/health", headers={"X-Request-ID": "known-id"})
    record = json.loads(logs.getvalue().splitlines()[-1])
    assert set(record) == {"event", "request_id", "method", "route", "status", "duration_ms"}
    assert record["request_id"] == "known-id"


def test_schema_documents_auth_and_safe_errors(app):
    schema = app.openapi()
    operation = schema["paths"]["/api/v1/projects"]["post"]
    assert operation["security"] == [{"HTTPBearer": []}]
    assert operation["responses"]["422"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }
    assert "security" not in schema["paths"]["/health"]["get"]


def test_body_timeout_is_bounded(app, auth):
    app.state.settings.body_timeout_seconds = 0.1

    async def run():
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "scheme": "http",
            "method": "POST",
            "path": "/api/v1/projects",
            "raw_path": b"/api/v1/projects",
            "query_string": b"",
            "root_path": "",
            "server": ("localhost", 8000),
            "client": ("127.0.0.1", 1),
            "headers": [
                (b"host", b"localhost:8000"),
                (b"authorization", f"Bearer {TOKEN}".encode()),
            ],
        }
        sent = []

        async def receive():
            await asyncio.sleep(5)

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        return sent

    assert asyncio.run(run())[0]["status"] == 408


def test_readiness_bounds_hung_dependency_and_one_inflight(app, client):
    import threading
    import time

    gate = threading.Event()
    engine = MagicMock()
    engine.connect.side_effect = lambda: gate.wait(2)
    app.state.engine = engine
    app.state.settings.database_timeout_seconds = 0.05
    try:
        start = time.monotonic()
        for _ in range(3):
            assert client.get("/ready").status_code == 503
        assert time.monotonic() - start < 0.8
        assert engine.connect.call_count == 1
        assert client.get("/health").status_code == 200
    finally:
        gate.set()
