"""Independent metadata/schema: no foreign key to any AppSec table."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    metadata = MetaData(schema="soc")


class Dataset(Base):
    __tablename__ = "datasets"
    __table_args__ = (CheckConstraint("label IN ('synthetic-demo','synthetic-test')"),)
    id: Mapped[UUID] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        UniqueConstraint("dataset_id", "source_id", "external_id"),
        UniqueConstraint("dataset_id", "id"),
        CheckConstraint("source_id IN ('synthetic-idp','synthetic-cloud')"),
        CheckConstraint("payload_digest ~ '^[0-9a-f]{64}$'"),
        CheckConstraint("octet_length(canonical::text) <= 2048"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True)
    dataset_id: Mapped[UUID] = mapped_column(ForeignKey("soc.datasets.id"))
    source_id: Mapped[str] = mapped_column(String(32))
    external_id: Mapped[str] = mapped_column(String(24))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    payload_digest: Mapped[str] = mapped_column(String(64))
    canonical: Mapped[dict[str, Any]] = mapped_column(JSONB)


Index(
    "ix_soc_events_history",
    SecurityEvent.dataset_id,
    SecurityEvent.ingested_at.desc(),
    SecurityEvent.id.desc(),
)
Index(
    "ix_soc_events_timeline", SecurityEvent.dataset_id, SecurityEvent.occurred_at, SecurityEvent.id
)


class CorrelationRun(Base):
    __tablename__ = "correlation_runs"
    __table_args__ = (
        UniqueConstraint("dataset_id", "idempotency_key"),
        UniqueConstraint("dataset_id", "id"),
        CheckConstraint("status IN ('queued','running','succeeded','failed')"),
        CheckConstraint("jsonb_array_length(event_ids) BETWEEN 1 AND 1000"),
        CheckConstraint("idempotency_key ~ '^[A-Za-z0-9_.-]{1,128}$'"),
        CheckConstraint("request_digest ~ '^[0-9a-f]{64}$' AND rules_digest ~ '^[0-9a-f]{64}$'"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    dataset_id: Mapped[UUID] = mapped_column(ForeignKey("soc.datasets.id"))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_digest: Mapped[str] = mapped_column(String(64))
    rules_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    event_ids: Mapped[list[str]] = mapped_column(JSONB)
    acceptance: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        UniqueConstraint("run_id"),
        CheckConstraint("operation = 'soc'"),
        CheckConstraint(
            "state IN ('queued','running','retry_pending','succeeded','terminal_failed')"
        ),
        CheckConstraint(
            "attempts = generation AND attempts >= 0 AND attempts <= max_attempts "
            "AND max_attempts BETWEEN 1 AND 5"
        ),
        CheckConstraint(
            "(state = 'running' AND lease_token IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND heartbeat_at IS NOT NULL "
            "AND attempt_deadline IS NOT NULL) OR "
            "(state != 'running' AND lease_token IS NULL AND lease_expires_at IS NULL "
            "AND heartbeat_at IS NULL AND attempt_deadline IS NULL)"
        ),
        CheckConstraint("request_id ~ '^[A-Za-z0-9_-]{1,64}$'"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("soc.correlation_runs.id"))
    operation: Mapped[str] = mapped_column(String(16), default="soc")
    state: Mapped[str] = mapped_column(String(32), default="queued")
    generation: Mapped[int] = mapped_column(Integer, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    lease_token: Mapped[UUID | None] = mapped_column()
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_id: Mapped[UUID | None] = mapped_column()
    request_id: Mapped[str] = mapped_column(String(64))
    error_code: Mapped[str | None] = mapped_column(String(32))


Index(
    "ix_soc_jobs_due",
    Job.next_attempt_at,
    Job.id,
    postgresql_where=text("state IN ('queued','retry_pending')"),
)
Index(
    "ix_soc_jobs_expired", Job.lease_expires_at, Job.id, postgresql_where=text("state = 'running'")
)


class Attempt(Base):
    __tablename__ = "job_attempts"
    __table_args__ = (
        UniqueConstraint("job_id", "generation"),
        CheckConstraint("generation > 0"),
        CheckConstraint("outcome IN ('running','succeeded','retry_pending','expired','failed')"),
        CheckConstraint(
            "(outcome = 'running' AND completed_at IS NULL) OR "
            "(outcome != 'running' AND completed_at IS NOT NULL)"
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(ForeignKey("soc.jobs.id"))
    generation: Mapped[int] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(32), default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        UniqueConstraint("run_id", "tracking_id"),
        ForeignKeyConstraint(
            ["job_id", "generation"], ["soc.job_attempts.job_id", "soc.job_attempts.generation"]
        ),
        ForeignKeyConstraint(
            ["dataset_id", "run_id"], ["soc.correlation_runs.dataset_id", "soc.correlation_runs.id"]
        ),
        CheckConstraint("rule_id IN ('auth-burst-success-v1','session-admin-grant-v1')"),
        CheckConstraint("evidence_state IN ('matched','incomplete')"),
        CheckConstraint("jsonb_array_length(evidence) BETWEEN 1 AND 21"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    dataset_id: Mapped[UUID] = mapped_column()
    run_id: Mapped[UUID] = mapped_column()
    job_id: Mapped[UUID] = mapped_column()
    generation: Mapped[int] = mapped_column(Integer)
    tracking_id: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(32))
    evidence_state: Mapped[str] = mapped_column(String(16))
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revision: Mapped[int] = mapped_column(Integer, default=0)
    disposition: Mapped[str | None] = mapped_column(String(32))


Index(
    "ix_soc_investigations_history",
    Investigation.dataset_id,
    Investigation.created_at.desc(),
    Investigation.id.desc(),
)


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"
    __table_args__ = (
        UniqueConstraint("investigation_id", "revision"),
        CheckConstraint("revision > 0 AND octet_length(note) <= 4000"),
        CheckConstraint(
            "disposition IN ('confirmed','false_positive','investigate','accepted_risk')"
        ),
        CheckConstraint(
            "feedback IS NULL OR feedback IN ('useful','incorrect','insufficient_evidence')"
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    investigation_id: Mapped[UUID] = mapped_column(ForeignKey("soc.investigations.id"))
    revision: Mapped[int] = mapped_column(Integer)
    disposition: Mapped[str] = mapped_column(String(32))
    note: Mapped[str] = mapped_column(String(1000))
    feedback: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Audit(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "event IN ('dataset.created','events.accepted','job.claimed',"
            "'job.succeeded','job.retry_pending','job.expired','job.failed',"
            "'review.created')"
        ),
        CheckConstraint("request_id ~ '^[A-Za-z0-9_-]{1,64}$'"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    event: Mapped[str] = mapped_column(String(32))
    object_id: Mapped[UUID] = mapped_column()
    generation: Mapped[int | None] = mapped_column(Integer)
    request_id: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
