import builtins
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ai_security_platform.api.app import create_app
from ai_security_platform.soc.contracts import Ingest, ReviewWrite
from ai_security_platform.soc.correlation import correlate
from ai_security_platform.soc.scenarios import scenario

pytestmark = pytest.mark.unit


def normalized(name):
    return [
        {
            "id": str(uuid4()),
            "payload_digest": "a" * 64,
            "occurred_at": e.occurred_at.isoformat(),
            "canonical": e.model_dump(mode="json"),
        }
        for e in scenario(name).events
    ]


@pytest.mark.parametrize(
    "name,count,state",
    [
        ("auth-burst", 1, "matched"),
        ("session-grant", 1, "matched"),
        ("clean", 0, None),
        ("incomplete", 1, "incomplete"),
    ],
)
def test_labelled_scenarios(name, count, state):
    data = normalized(name)
    result = correlate(data)
    assert len(result) == count
    assert result == correlate(list(reversed(data)))
    if count:
        assert result[0]["evidence_state"] == state
        assert len(result[0]["evidence"]) >= (2 if state == "matched" else 1)


@pytest.mark.parametrize(
    "field,value",
    [
        ("actor", "user@example.com"),
        ("actor", "actor-SYNTHETIC_SECRET_hidden"),
        ("event_id", "../../secret"),
        ("event_id", "a" * 100),
        ("session_id", "https://example.com"),
        ("occurred_at", "2026-01-01T00:00:00"),
        ("source_id", "real-idp"),
        ("format", "shell"),
        ("action", "exec"),
        ("password", "SYNTHETIC_SECRET_hidden"),
        ("version", 2),
    ],
)
def test_strict_synthetic_payloads(field, value):
    data = scenario("clean").model_dump(mode="json")
    data["events"][0][field] = value
    with pytest.raises(ValidationError):
        Ingest.model_validate(data)


def test_budget_and_notes():
    data = scenario("clean").model_dump(mode="json")
    with pytest.raises(ValidationError):
        Ingest.model_validate({"events": data["events"] * 21})
    note = ReviewWrite(
        expected_revision=0,
        disposition="investigate",
        note="SYNTHETIC_SECRET_hidden password='fake' <script>test</script>",
    )
    assert "SYNTHETIC_SECRET_hidden" not in note.note
    assert "<script>" not in note.note


def test_no_causation_by_time_or_cross_actor():
    data = normalized("session-grant")
    data[0]["canonical"]["actor"] = "actor-other"
    assert correlate(data)[0]["evidence_state"] == "incomplete"
    data = normalized("auth-burst")
    data[-1]["occurred_at"] = (datetime(2026, 1, 1, tzinfo=UTC) + timedelta(hours=1)).isoformat()
    assert correlate(data) == []


def test_disabled_independently_without_imports(settings, monkeypatch):
    original = builtins.__import__

    def deny(name, *args, **kwargs):
        if name.startswith("ai_security_platform.soc"):
            raise ImportError("optional_module_removed")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", deny)
    with TestClient(create_app(settings), base_url="http://localhost:8000") as client:
        assert client.get("/health").status_code == 200
        assert (
            client.get(
                "/api/v1/soc/rules",
                headers={"Authorization": "Bearer " + settings.api_token.get_secret_value()},
            ).status_code
            == 404
        )


def test_enabled_http_security_and_sanitization(settings, caplog):
    settings = settings.model_copy(update={"soc_enabled": True})
    with TestClient(create_app(settings), base_url="http://localhost:8000") as client:
        path = f"/api/v1/soc/datasets/{uuid4()}/events"
        assert client.get("/api/v1/soc/rules").status_code == 401
        auth = {"Authorization": "Bearer " + settings.api_token.get_secret_value()}
        assert client.get("/api/v1/soc/rules", headers=auth).status_code == 200
        assert (
            client.get(
                "/api/v1/soc/rules", headers=auth | {"Origin": "http://evil.example"}
            ).status_code
            == 403
        )
        invalid = scenario("clean").model_dump(mode="json")
        invalid["events"][0]["password"] = "SYNTHETIC_SECRET_hidden"
        response = client.post(path, headers=auth | {"Idempotency-Key": "invalid"}, json=invalid)
        assert response.status_code == 422
        assert "SYNTHETIC_SECRET_hidden" not in response.text + caplog.text
        assert client.post(path, headers=auth, content=b"x" * 16385).status_code == 413
        assert "password" not in json.dumps(response.json().get("details", {})) or (
            "SYNTHETIC_SECRET_hidden" not in response.text
        )
