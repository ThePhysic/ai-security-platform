from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ProviderId = Literal["deterministic-v1", "openai-v1"]
Disposition = Literal[
    "confirmed", "false_positive", "investigate", "accepted_risk", "remediation_planned"
]
ToolName = Literal["finding", "source", "rule", "coverage", "context"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class TriageSubmission(StrictModel):
    provider: ProviderId = "deterministic-v1"
    operation_id: UUID | None = None
    consent_id: UUID | None = None


class ConsentCreate(StrictModel):
    operation_id: UUID
    finding_id: UUID
    config_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    data_categories: list[Literal["finding", "redacted_source", "rule", "coverage", "context"]] = (
        Field(min_length=1, max_length=5)
    )
    acknowledge_confidentiality_risk: Literal[True]

    @field_validator("acknowledge_confidentiality_risk", mode="before")
    @classmethod
    def explicit_boolean(cls, value: object) -> object:
        if value is not True:
            raise ValueError("explicit_consent_required")
        return value


class ReviewWrite(StrictModel):
    expected_revision: int = Field(ge=0, le=2147483646)
    disposition: Disposition
    note: str = Field(default="", max_length=2000)
    triage_run_id: UUID | None = None
    feedback: Literal["agree", "disagree", "uncertain"] | None = None


class FindingArgs(StrictModel):
    finding_id: UUID


class SourceArgs(FindingArgs):
    start_line: int = Field(ge=1, le=1048576)
    end_line: int = Field(ge=1, le=1048576)


class EmptyArgs(StrictModel):
    pass


class ContextArgs(StrictModel):
    limit: int = Field(default=3, ge=1, le=5)


class ToolCall(StrictModel):
    name: ToolName
    arguments: dict[str, Any] = Field(max_length=3)


class Citation(StrictModel):
    evidence_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: ToolName
    snapshot_id: UUID
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    filepath: str = Field(max_length=240)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class Evidence(StrictModel):
    citation: Citation
    data: dict[str, Any]


class Assessment(StrictModel):
    assessment: Literal["needs_review", "likely_false_positive", "abstain"]
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    summary: str = Field(min_length=1, max_length=1200)
    remediation: str = Field(min_length=1, max_length=1200)
    reason: Literal[
        "evidence_supported", "insufficient_evidence", "unsupported_rule", "source_unavailable"
    ]
    citations: list[Citation] = Field(max_length=8)


class ProviderStep(StrictModel):
    call: ToolCall | None
    final: Assessment | None

    @model_validator(mode="after")
    def exactly_one(self) -> "ProviderStep":
        if (self.call is None) == (self.final is None):
            raise ValueError("one_action_required")
        return self
