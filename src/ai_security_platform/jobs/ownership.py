"""Shared PostgreSQL lease predicates; no target or optional-module dependencies."""

from datetime import datetime
from typing import Protocol
from uuid import UUID


class OwnedJob(Protocol):
    operation: str
    state: str
    generation: int
    lease_token: UUID | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    attempt_deadline: datetime | None


class Ownership(Protocol):
    @property
    def operation(self) -> str: ...
    @property
    def generation(self) -> int: ...
    @property
    def token(self) -> UUID: ...


def owned(job: OwnedJob, lease: Ownership, now: datetime) -> bool:
    return (
        job.operation == lease.operation
        and job.state == "running"
        and job.generation == lease.generation
        and job.lease_token == lease.token
        and job.lease_expires_at is not None
        and job.lease_expires_at > now
        and job.attempt_deadline is not None
        and job.attempt_deadline > now
    )


def clear_lease(job: OwnedJob) -> None:
    job.lease_token = None
    job.lease_expires_at = None
    job.heartbeat_at = None
    job.attempt_deadline = None
