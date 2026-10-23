"""Narrow provider protocol. Only this module can contact the fixed hosted endpoint."""

import json
import os
import re
from collections.abc import Callable
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from ai_security_platform.agent.contracts import Assessment, Evidence, ProviderStep, ToolCall
from ai_security_platform.agent.policy import MODEL, PROMPT, AgentError
from ai_security_platform.agent.tools import ARGUMENTS
from ai_security_platform.snapshots.policy import canonical


class Provider(Protocol):
    hosted: bool

    def input_bytes(self, finding_id: str, evidence: list[Evidence]) -> int: ...

    def step(self, finding_id: str, evidence: list[Evidence], timeout: float) -> ProviderStep: ...


class DeterministicProvider:
    hosted = False

    def input_bytes(self, finding_id: str, evidence: list[Evidence]) -> int:
        return len(canonical([row.model_dump(mode="json") for row in evidence])) + len(
            PROMPT.encode()
        )

    def step(self, finding_id: str, evidence: list[Evidence], timeout: float) -> ProviderStep:
        results = {row.citation.kind: row for row in evidence}
        if "finding" not in results:
            return ProviderStep(
                call=ToolCall(name="finding", arguments={"finding_id": finding_id}), final=None
            )
        finding = results["finding"].data
        if "source" not in results:
            return ProviderStep(
                call=ToolCall(
                    name="source",
                    arguments={
                        "finding_id": finding_id,
                        "start_line": finding["start_line"],
                        "end_line": finding["end_line"],
                    },
                ),
                final=None,
            )
        for name in ("rule", "coverage", "context"):
            if name not in results:
                return ProviderStep(
                    call=ToolCall(
                        name=name, arguments={"finding_id": finding_id} if name == "rule" else {}
                    ),
                    final=None,
                )
        source = results["source"].data.get("text", "")
        rule = finding["rule_id"]
        supported = (
            not finding["synthetic"]
            and results["rule"].data["historical_policy_matches"]
            and (
                (rule in {"platform.python.eval", "platform.javascript.eval"} and "eval(" in source)
                or (rule == "platform.python.sql-format" and "execute(" in source)
                or (rule == "platform.javascript.sql-concat" and ".query(" in source)
                or (rule == "platform.python.shell" and "shell=True" in source)
                or (rule == "platform.javascript.exec" and "exec(" in source)
                or (rule == "platform.ci.write-all" and "write-all" in source)
                or (rule == "platform.ci.mutable-action" and "uses:" in source)
            )
        )
        # Both the finding identity and actual retrieved source govern this decision.
        safe_literal = bool(
            supported
            and rule.endswith(".eval")
            and re.fullmatch(r"\s*(?:\w+\s*=\s*)?eval\(\s*(['\"])1\+1\1\s*\)\s*;?\s*", source)
        )
        assessment = Assessment(
            assessment="likely_false_positive"
            if safe_literal
            else "needs_review"
            if supported
            else "abstain",
            confidence=0.65 if safe_literal else 0.7 if supported else 0,
            summary=(
                (
                    "The cited expression evaluates a fixed literal; inspect "
                    "surrounding data flow before dismissing the finding."
                )
                if safe_literal
                else (
                    "The cited source contains the reported risky construct; input "
                    "control and exploitability remain unproven."
                )
                if supported
                else (
                    "Available source and trusted rule context do not support a "
                    "reliable assessment."
                )
            ),
            remediation=results["rule"].data["guidance"]
            if supported
            else "Request focused human investigation; do not apply an automatic fix.",
            reason="evidence_supported" if supported else "insufficient_evidence",
            citations=[
                row.citation
                for row in evidence
                if row.citation.kind in {"finding", "source", "rule", "coverage"}
            ],
        )
        return ProviderStep(call=None, final=assessment)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


Transport = Callable[[bytes, float], bytes]


class OpenAIProvider:
    hosted = True

    def __init__(self, transport: Transport):
        self.transport = transport

    @classmethod
    def from_environment(cls) -> "OpenAIProvider":
        # The API, scanner worker and launcher never load this provider-only variable.
        key = os.environ.get("ASP_HOSTED_API_KEY", "")
        if not key or len(key) > 512 or any(ord(char) < 33 or ord(char) > 126 for char in key):
            raise AgentError("provider_unavailable")
        opener = build_opener(ProxyHandler({}), NoRedirect())

        def transport(body: bytes, timeout: float) -> bytes:
            request = Request(
                "https://api.openai.com/v1/responses",
                data=body,
                headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with opener.open(request, timeout=timeout) as response:
                    raw: bytes = response.read(65537)
                    if len(raw) > 65536:
                        raise AgentError("invalid_provider_output")
                    return raw
            except HTTPError as error:
                raise AgentError(
                    "provider_rate_limited" if error.code == 429 else "provider_unavailable",
                    retryable=error.code in {429, 500, 502, 503, 504},
                ) from None
            except (URLError, TimeoutError, OSError):
                raise AgentError("provider_timeout", retryable=True) from None

        return cls(transport)

    def step(self, finding_id: str, evidence: list[Evidence], timeout: float) -> ProviderStep:
        return self._step(self.payload(finding_id, evidence), timeout)

    def input_bytes(self, finding_id: str, evidence: list[Evidence]) -> int:
        return len(self.payload(finding_id, evidence))

    def payload(self, finding_id: str, evidence: list[Evidence]) -> bytes:
        tools = []
        for name, arguments in ARGUMENTS.items():
            schema = arguments.model_json_schema()
            schema["required"] = list(schema.get("properties", {}))
            for field in schema.get("properties", {}).values():
                field.pop("default", None)
            tools.append(
                {
                    "type": "function",
                    "name": name,
                    "description": "Scoped read-only " + name,
                    "strict": True,
                    "parameters": schema,
                }
            )
        body = {
            "model": MODEL,
            "store": False,
            "background": False,
            "reasoning": {"effort": "none"},
            "max_output_tokens": 2048,
            "parallel_tool_calls": False,
            "tools": tools,
            "instructions": PROMPT,
            "input": canonical(
                {
                    "finding_id": finding_id,
                    "untrusted_evidence": [v.model_dump(mode="json") for v in evidence],
                }
            ).decode(),
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "security_assessment",
                    "strict": True,
                    "schema": Assessment.model_json_schema(),
                }
            },
        }
        return canonical(body)

    def _step(self, payload: bytes, timeout: float) -> ProviderStep:
        try:
            raw = self.transport(payload, timeout)
            if len(raw) > 65536:
                raise ValueError("output_limit")
            result = json.loads(raw)
            if result.get("status") != "completed":
                raise ValueError("incomplete_output")
            items = result["output"]
            actions = [item for item in items if item.get("type") in {"function_call", "message"}]
            if len(actions) != 1:
                raise ValueError("one_action_required")
            action = actions[0]
            if action["type"] == "function_call":
                return ProviderStep(
                    call=ToolCall(name=action["name"], arguments=json.loads(action["arguments"])),
                    final=None,
                )
            texts = [item["text"] for item in action["content"] if item["type"] == "output_text"]
            if len(texts) != 1:
                raise ValueError("invalid_output")
            return ProviderStep(call=None, final=Assessment.model_validate_json(texts[0]))
        except (ValueError, KeyError, TypeError, RecursionError, AttributeError):
            raise AgentError("invalid_provider_output") from None
