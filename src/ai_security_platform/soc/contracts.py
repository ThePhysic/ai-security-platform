"""No free-form source payloads, real identities, credentials or enterprise adapters."""

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ai_security_platform.agent.policy import plain
from ai_security_platform.snapshots.policy import canonical, digest

Identifier = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,23}$")]
Actor = Annotated[str, Field(pattern=r"^actor-[a-z0-9-]{1,18}$")]
SessionID = Annotated[str, Field(pattern=r"^session-[a-z0-9-]{1,16}$")]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class DatasetCreate(Contract):
    id: UUID
    label: Literal["synthetic-demo", "synthetic-test"] = "synthetic-demo"


class EventInput(Contract):
    version: Literal[1] = 1
    event_id: Identifier
    actor: Actor
    occurred_at: datetime
    session_id: SessionID | None = None

    @field_validator("occurred_at")
    @classmethod
    def timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or not 2020 <= value.year <= 2099:
            raise ValueError("bounded_timezone_timestamp_required")
        return value.astimezone(UTC)


class IdentityEvent(EventInput):
    format: Literal["identity-v1"]
    source_id: Literal["synthetic-idp"]
    action: Literal["authentication_failed", "authentication_succeeded", "access_denied"]


class CloudEvent(EventInput):
    format: Literal["cloud-iam-v1"]
    source_id: Literal["synthetic-cloud"]
    action: Literal["admin_granted", "permission_removed", "readonly_granted"]
    resource: Annotated[str, Field(pattern=r"^resource-[a-z0-9-]{1,15}$")]


Event = Annotated[IdentityEvent | CloudEvent, Field(discriminator="format")]


class Ingest(Contract):
    version: Literal[1] = 1
    events: Annotated[list[Event], Field(min_length=1, max_length=20)]


class ReviewWrite(Contract):
    expected_revision: Annotated[int, Field(ge=0, le=2147483646)]
    disposition: Literal["confirmed", "false_positive", "investigate", "accepted_risk"]
    note: Annotated[str, Field(max_length=1000)] = ""
    feedback: Literal["useful", "incorrect", "insufficient_evidence"] | None = None

    @field_validator("note")
    @classmethod
    def safe_note(cls, value: str) -> str:
        # Same heuristic policy as AppSec; never a comprehensive DLP guarantee.
        return plain(value)[:1000]


def fingerprint(value: object) -> str:
    return digest(canonical(value))


RULES = {
    "auth-burst-success-v1": {
        "window_seconds": 600,
        "minimum_failures": 3,
        "meaning": "Three failed authentications followed by success for the same synthetic actor.",
        "limitation": "Observed sequence only; compromise and causation are not established.",
    },
    "session-admin-grant-v1": {
        "window_seconds": 900,
        "meaning": "Admin grant sharing an explicit actor/session with an earlier authentication.",
        "limitation": "A shared synthetic session establishes association, not malicious intent.",
    },
}
RULE_DIGEST = fingerprint(RULES)
