"""Offline provider wire/security checks; no network or model credentials required."""

import json
import time
from uuid import uuid4

import pytest
from pydantic import ValidationError

from ai_security_platform.agent.contracts import ConsentCreate, ProviderStep, ReviewWrite, ToolCall
from ai_security_platform.agent.engine import bounded_step
from ai_security_platform.agent.policy import MODEL, AgentError, plain, redact
from ai_security_platform.agent.providers import DeterministicProvider, OpenAIProvider

pytestmark = [pytest.mark.unit, pytest.mark.agent]


@pytest.mark.parametrize("name", ["shell", "docker", "http", "write", "plugins", "remediate"])
def test_unauthorized_tools_cannot_be_parsed(name):
    with pytest.raises(ValidationError):
        ToolCall(name=name, arguments={})


@pytest.mark.parametrize(
    "raw",
    [
        b"not JSON",
        b"[]",
        b"{}",
        b"x" * 65537,
        b'{"status":"incomplete","output":[]}',
        b'{"status":"completed","output":[{"type":"function_call","name":"shell","arguments":"{}"}]}',
        b'{"status":"completed","output":[{"type":"message","content":[{"type":"refusal","refusal":"no"}]}]}',
    ],
    ids=[
        "invalid-json",
        "array",
        "missing-fields",
        "oversized",
        "incomplete",
        "unknown-tool",
        "refusal",
    ],
)
def test_invalid_incomplete_and_unauthorized_hosted_output(raw):
    with pytest.raises(AgentError, match="invalid_provider_output"):
        OpenAIProvider(lambda *_: raw).step(str(uuid4()), [], 1)


def test_hosted_fixed_schema_and_no_builtin_tools():
    request = json.loads(OpenAIProvider(lambda *_: b"unused").payload(str(uuid4()), []))
    assert request["model"] == MODEL and request["store"] is False
    assert request["background"] is False and request["parallel_tool_calls"] is False
    assert {row["name"] for row in request["tools"]} == {
        "finding",
        "source",
        "rule",
        "coverage",
        "context",
    }
    assert all(row["type"] == "function" and row["strict"] for row in request["tools"])
    assert all(row["parameters"]["additionalProperties"] is False for row in request["tools"])
    assert "Authorization" not in json.dumps(request)


def test_provider_credentials_not_required_for_offline_and_safe_errors(monkeypatch):
    monkeypatch.delenv("ASP_HOSTED_API_KEY", raising=False)
    assert DeterministicProvider().step(str(uuid4()), [], 1).call.name == "finding"
    with pytest.raises(AgentError, match="provider_unavailable"):
        OpenAIProvider.from_environment()
    secret = "SYNTHETIC_SECRET_" + "z" * 20

    class Broken(DeterministicProvider):
        def step(self, *_):
            raise RuntimeError(secret)

    with pytest.raises(AgentError) as failure:
        bounded_step(Broken(), str(uuid4()), [], 1)
    assert secret not in str(failure.value)


def test_provider_wall_clock_timeout_requires_worker_restart():
    class Blocked(DeterministicProvider):
        def step(self, *_):
            time.sleep(0.1)
            return ProviderStep(call=ToolCall(name="context", arguments={}), final=None)

    started = time.monotonic()
    with pytest.raises(AgentError, match="provider_timeout") as failure:
        bounded_step(Blocked(), str(uuid4()), [], 0.02)
    assert time.monotonic() - started < 0.09 and failure.value.restart


def test_confidentiality_and_plaintext_are_idempotent():
    secret = "AKIA" + "Z" * 16
    note = plain('<script>bad</script> [x](javascript:bad) password="' + secret + '"\x1b')
    assert (
        secret not in note
        and "<script>" not in note
        and "](javascript" not in note
        and "\x1b" not in note
    )
    assert plain(note) == note
    assert secret not in redact(secret)
    with pytest.raises(ValidationError):
        ReviewWrite(expected_revision=0, disposition="confirmed", reviewer="spoof")


@pytest.mark.parametrize("ack", [False, 1, "true"])
def test_consent_requires_explicit_json_boolean(ack):
    with pytest.raises(ValidationError):
        ConsentCreate(
            operation_id=uuid4(),
            finding_id=uuid4(),
            config_digest="a" * 64,
            data_categories=["finding"],
            acknowledge_confidentiality_risk=ack,
        )
