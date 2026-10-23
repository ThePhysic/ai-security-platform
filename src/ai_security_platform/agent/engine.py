"""Small explicit tool loop. Permission and publication checks are outside the model."""

import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event, Thread
from typing import Any

from ai_security_platform.agent.contracts import Assessment, Evidence, ProviderStep
from ai_security_platform.agent.policy import (
    INPUT_RATE,
    LIMITS,
    OUTPUT_RATE,
    AgentError,
    Limits,
    plain,
)
from ai_security_platform.agent.providers import Provider
from ai_security_platform.agent.tools import EvidenceTools


@dataclass(frozen=True)
class Investigation:
    assessment: Assessment
    trace: list[dict[str, Any]]
    usage: dict[str, Any]


def bounded_step(
    provider: Provider, finding_id: str, results: list[Evidence], timeout: float
) -> ProviderStep:
    completed = Event()
    response: list[ProviderStep] = []
    failures: list[AgentError] = []

    def invoke() -> None:
        try:
            response.append(provider.step(finding_id, results, timeout))
        except AgentError as error:
            failures.append(error)
        except Exception:
            failures.append(AgentError("provider_unavailable"))
        finally:
            completed.set()

    Thread(target=invoke, daemon=True, name="bounded-provider").start()
    if not completed.wait(timeout):
        raise AgentError("provider_timeout", retryable=True, restart=True)
    if failures:
        raise failures[0]
    try:
        return ProviderStep.model_validate(response[0].model_dump())
    except (ValueError, TypeError, AttributeError, IndexError):
        raise AgentError("invalid_provider_output") from None


def validate_assessment(value: Assessment, tools: EvidenceTools) -> Assessment:
    value = Assessment.model_validate(value.model_dump())
    for citation in value.citations:
        known = tools.evidence.get(citation.evidence_id)
        if known is None or citation != known.citation:
            raise AgentError("invalid_citation")
    kinds = {c.kind for c in value.citations}
    if value.assessment != "abstain" and (
        not {"finding", "source"} <= kinds or value.reason != "evidence_supported"
    ):
        raise AgentError("insufficient_evidence")
    if value.assessment == "abstain" and value.confidence > 0.25:
        raise AgentError("invalid_provider_output")
    value.summary, value.remediation = plain(value.summary), plain(value.remediation)
    return value


def investigate(
    provider: Provider,
    tools: EvidenceTools,
    authorize: Callable[[int, int, int], None],
    *,
    limits: Limits = LIMITS,
) -> Investigation:
    results: list[Evidence] = []
    calls = tokens = reserved = 0
    while calls < limits.provider_calls:
        tools.check_time()
        # UTF-8 bytes + framing reserve is an intentionally conservative token bound,
        # not tokenizer measurement. Reserve the entire output cap before every send.
        input_bound = provider.input_bytes(str(tools.finding_id), results) + 4096
        token_bound = input_bound + limits.output_tokens
        cost = (
            (input_bound * INPUT_RATE + limits.output_tokens * OUTPUT_RATE + 999999) // 1000000
            if provider.hosted
            else 0
        )
        if tokens + token_bound > limits.token_upper_bound:
            raise AgentError("token_budget")
        if reserved + cost > limits.cost_micro_usd:
            raise AgentError("cost_budget")
        calls += 1
        authorize(calls, cost, token_bound)  # fenced reservation before every send/retry
        tokens += token_bound
        reserved += cost
        remaining = limits.seconds - (time.monotonic() - tools.started)
        if remaining <= 0:
            raise AgentError("time_budget")
        started = time.monotonic()
        step = bounded_step(provider, str(tools.finding_id), results, min(5.0, remaining))
        tools.check_time()
        if time.monotonic() - started > min(5.0, remaining):
            raise AgentError("provider_timeout", retryable=True)
        if step.final is not None:
            assessment = validate_assessment(step.final, tools)
            return Investigation(
                assessment,
                list(tools.trace),
                {
                    "provider_calls": calls,
                    "tool_calls": tools.calls,
                    "context_bytes": tools.context_bytes,
                    "token_upper_bound": tokens,
                    "reserved_micro_usd": reserved,
                    "billing_measured": False,
                    "duration_ms": int((time.monotonic() - tools.started) * 1000),
                },
            )
        assert step.call is not None
        results.append(tools.call(step.call))
    raise AgentError("tool_budget")
