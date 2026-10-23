"""Narrow wire contracts; no executable, argv, mount or daemon options."""

from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class LauncherHello(BaseModel):
    model_config = ConfigDict(extra="forbid")
    launcher_id: UUID
    registry_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    gate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class LauncherPoll(BaseModel):
    model_config = ConfigDict(extra="forbid")
    launcher_id: UUID


class InvocationIdentity(LauncherPoll):
    generation: int = Field(ge=1, le=5)
    lease_token: UUID = Field(repr=False)


class LauncherResult(InvocationIdentity):
    # Typed adapter validation is performed again before staging and publication.
    result: dict[str, Any] = Field(max_length=16)
