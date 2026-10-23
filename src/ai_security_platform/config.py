"""Validated settings. Never format raw validation errors or settings into logs."""

import re
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class ConfigurationError(RuntimeError):
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ASP_", env_file=".env", extra="ignore", hide_input_in_errors=True
    )

    database_url: SecretStr = Field(repr=False)
    api_token: SecretStr = Field(repr=False)
    allowed_hosts: list[str] = ["127.0.0.1:8000", "localhost:8000"]
    allowed_origins: list[str] = ["http://127.0.0.1:8000", "http://localhost:8000"]
    request_body_limit: int = Field(default=16384, ge=128, le=65536)
    authorization_header_limit: int = Field(default=4096, ge=256, le=4096)
    body_timeout_seconds: float = Field(default=5, ge=0.1, le=30)
    database_timeout_seconds: int = Field(default=2, ge=1, le=10)
    snapshot_spool: Path = Path(".local/snapshot-spool")
    snapshot_retention_seconds: int = Field(default=86400, ge=60, le=604800)
    pending_jobs_per_project: int = Field(default=1000, ge=2, le=10000)
    lease_seconds: float = Field(default=10, ge=0.25, le=120)
    heartbeat_seconds: float = Field(default=2, ge=0.05, le=30)
    attempt_seconds: float = Field(default=30, ge=0.5, le=300)
    poll_seconds: float = Field(default=0.5, ge=0.05, le=5)
    retry_base_seconds: float = Field(default=0.5, ge=0.01, le=30)

    @model_validator(mode="after")
    def bounded_worker_timing(self) -> "Settings":
        if (
            self.heartbeat_seconds >= self.lease_seconds
            or self.attempt_seconds < self.lease_seconds
        ):
            raise ValueError("Heartbeat must precede lease expiry within the hard deadline")
        return self

    @field_validator("database_url")
    @classmethod
    def database_is_postgres(cls, value: SecretStr) -> SecretStr:
        try:
            url = make_url(value.get_secret_value())
            valid = (
                url.drivername == "postgresql+psycopg"
                and bool(url.host and url.database and url.username and url.password)
                and not url.query
            )
        except Exception:
            valid = False
        if not valid:
            raise ValueError("A PostgreSQL Psycopg connection is required")
        return value

    @field_validator("api_token")
    @classmethod
    def strong_token(cls, value: SecretStr) -> SecretStr:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,256}", value.get_secret_value()):
            raise ValueError("An independently generated URL-safe bearer secret is required")
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def exact_hosts(cls, values: list[str]) -> list[str]:
        if not values or any(
            not re.fullmatch(r"(?:localhost|127\.0\.0\.1)(?::[1-9][0-9]{0,4})?", v)
            or (":" in v and int(v.rsplit(":", 1)[1]) > 65535)
            for v in values
        ):
            raise ValueError("Explicit local Host values are required")
        return list(dict.fromkeys(values))

    @field_validator("allowed_origins")
    @classmethod
    def exact_origins(cls, values: list[str]) -> list[str]:
        for value in values:
            parsed = urlsplit(value)
            if (
                parsed.scheme != "http"
                or parsed.hostname not in {"127.0.0.1", "localhost"}
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
                or parsed.port is None
                or value != f"http://{parsed.hostname}:{parsed.port}"
            ):
                raise ValueError("Explicit local origins including port are required")
        return list(dict.fromkeys(values))


def load_settings() -> Settings:
    try:
        return Settings()
    except Exception:
        raise ConfigurationError(
            "Invalid application configuration; check required settings"
        ) from None
