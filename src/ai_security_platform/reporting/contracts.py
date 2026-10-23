"""Versioned public report schema shared by CLI and API, with scoped file references."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ai_security_platform.domain.findings import FindingRead
from ai_security_platform.domain.scans import ScanRead
from ai_security_platform.snapshots.policy import validate_path


class FileReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lines: int = Field(ge=0, le=1048576)


class SourceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    snapshot_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified: Literal[True]
    files: dict[str, FileReference] = Field(max_length=512)


class ReportFinding(FindingRead):
    scanner_id: str = Field(pattern=r"^[a-z0-9-]{1,32}$")


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    reporting_version: Literal["scanner-report-1"]
    scan: ScanRead
    findings: list[ReportFinding] = Field(max_length=1000)
    source: SourceReference
    limitations: list[str] = Field(max_length=10)
    ai_opinions_applied: Literal[False]
    evaluation_labels_applied: Literal[False]

    @model_validator(mode="after")
    def scoped_references(self) -> "Report":
        if self.scan.snapshot_id != self.source.snapshot_id:
            raise ValueError("invalid_report_scope")
        stages = {r.id: r.scanner_id for r in self.scan.scanner_runs}
        for path in self.source.files:
            validate_path(path)
        for row in self.findings:
            if (
                row.scan_run_id != self.scan.id
                or stages.get(row.scanner_run_id) != row.scanner_id
                or row.filepath not in self.source.files
                or not 1 <= row.start_line <= row.end_line <= self.source.files[row.filepath].lines
                or row.evidence.get("manifest_digest") != self.source.manifest_digest
            ):
                raise ValueError("invalid_report_scope")
        return self
