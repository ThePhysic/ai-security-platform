import unicodedata
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=200)

    @field_validator("name")
    @classmethod
    def no_control_characters(cls, value: str) -> str:
        if any(unicodedata.category(c).startswith("C") for c in value):
            raise ValueError("Control characters are not allowed")
        return value


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str
    created_at: datetime
