from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScannerRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    scanner_id: str
    adapter_version: str
    status: str
    coverage: dict[str, int | str | bool | list[str]]
    error_code: str | None
    synthetic: bool = True
    provenance: dict[str, str | int] = Field(default_factory=dict)


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    project_id: UUID
    snapshot_id: UUID
    profile_id: str
    profile_digest: str
    status: ScanStatus
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    scanner_runs: list[ScannerRead] = Field(default_factory=list)


class ScanPage(BaseModel):
    items: list[ScanRead]
    next_cursor: str | None
