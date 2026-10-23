from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    scan_run_id: UUID
    scanner_run_id: UUID
    occurrence_key: str
    tracking_fingerprint: str
    fingerprint_version: int
    rule_id: str
    category: str
    severity: str
    original_severity: str
    description: str
    filepath: str
    start_line: int
    end_line: int
    created_at: datetime
    synthetic: Literal[True] = True


class FindingPage(BaseModel):
    items: list[FindingRead]
    next_cursor: str | None
