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
    rule_id: str = Field(max_length=128, pattern=r"^[A-Za-z0-9_.:/-]{1,128}$")
    category: Literal["synthetic", "sast", "vulnerability", "secret", "misconfiguration"] = (
        "synthetic"
    )
    severity: Literal["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    original_severity: str = Field(default="synthetic-medium", max_length=32)
    description: str = Field(
        default=("Synthetic test marker; not a security detection."), max_length=256
    )
    filepath: str = Field(max_length=240)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    evidence: dict[str, str | int] = Field(default_factory=dict, max_length=8)
    synthetic: bool = True


class AdapterResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scanner_id: Literal["fake-patterns", "fake-config", "semgrep", "trivy"]
    findings: list[NormalizedFinding] = Field(max_length=1000)
    files_scanned: int = Field(ge=0, le=512)
    excluded_files: int = Field(ge=0)
    excluded_directories: int = Field(ge=0)
    complete: bool = True
    warnings: list[str] = Field(default_factory=list, max_length=16)
    provenance: dict[str, str | int] = Field(default_factory=dict, max_length=16)
    policy_files_ignored: int = Field(default=0, ge=0, le=512)
    suppression_tokens_neutralized: int = Field(default=0, ge=0, le=1048576)


class ScannerAdapter(Protocol):
    def scan(self, source: VerifiedSnapshot) -> AdapterResult: ...
