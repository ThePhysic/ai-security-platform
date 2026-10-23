from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from ai_security_platform.snapshots.policy import canonical, digest
from ai_security_platform.snapshots.store import VerifiedSnapshot

SCANNERS = ("fake-patterns", "fake-config")
PROFILE_DIGEST = digest(canonical({"id": "fake-v1", "scanners": SCANNERS, "adapter": "fake-1"}))


class NormalizedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    occurrence_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    tracking_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_id: Literal["fake.marker.v1", "fake.config.v1"]
    category: Literal["synthetic"] = "synthetic"
    severity: Literal["MEDIUM"] = "MEDIUM"
    original_severity: Literal["synthetic-medium"] = "synthetic-medium"
    description: Literal["Synthetic test marker; not a security detection."] = (
        "Synthetic test marker; not a security detection."
    )
    filepath: str = Field(max_length=240)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class AdapterResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scanner_id: Literal["fake-patterns", "fake-config"]
    findings: list[NormalizedFinding] = Field(max_length=1000)
    files_scanned: int = Field(ge=0, le=512)
    excluded_files: int = Field(ge=0)
    excluded_directories: int = Field(ge=0)


class ScannerAdapter(Protocol):
    def scan(self, source: VerifiedSnapshot) -> AdapterResult: ...
