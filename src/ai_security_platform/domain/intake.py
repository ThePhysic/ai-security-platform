from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SnapshotRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: UUID
    snapshot_key: str = Field(pattern=r"^[0-9a-f]{32}$")
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class SnapshotRead(BaseModel):
    id: UUID
    project_id: UUID
    snapshot_key: str
    manifest_digest: str
    content_digest: str
    file_count: int
    byte_count: int
    expires_at: datetime | None


class ScanSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: UUID
    snapshot_id: UUID
    profile_id: Literal["fake-v1"]


class ScanAccepted(BaseModel):
    id: UUID
    status: str
    status_url: str
