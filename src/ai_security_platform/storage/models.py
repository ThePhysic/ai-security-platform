from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ai_security_platform.storage.base import Base


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("char_length(btrim(name)) BETWEEN 1 AND 200", name="name_length"),
        CheckConstraint("name !~ '[[:cntrl:]]'", name="name_controls"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ScannerRun(Base):
    __tablename__ = "scanner_runs"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "id", name="uq_scanner_scan_id"),
        UniqueConstraint("scan_run_id", "scanner_id", name="uq_scanner_slot"),
        CheckConstraint("status IN ('queued','running','succeeded','failed')", name="status"),
        CheckConstraint("scanner_id ~ '^[a-z0-9-]{1,32}$'", name="scanner_id"),
        CheckConstraint("winning_generation IS NULL OR winning_generation > 0", name="winner"),
        CheckConstraint(
            "jsonb_typeof(coverage) = 'object' AND octet_length(coverage::text) <= 4096",
            name="coverage",
        ),
        CheckConstraint(
            "jsonb_typeof(provenance) = 'object' AND octet_length(provenance::text) <= 4096",
            name="provenance",
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scan_run_id: Mapped[UUID] = mapped_column(ForeignKey("scan_runs.id"))
    scanner_id: Mapped[str] = mapped_column(String(32))
    adapter_version: Mapped[str] = mapped_column(String(32), default="fake-1")
    status: Mapped[str] = mapped_column(String(16), default="queued")
    coverage: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    winning_generation: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provenance: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )

    @property
    def synthetic(self) -> bool:
        return self.scanner_id.startswith("fake-")


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        UniqueConstraint("scanner_run_id", name="uq_job_scanner"),
        UniqueConstraint("id", "scanner_run_id", name="uq_job_scanner_identity"),
        UniqueConstraint("triage_run_id", name="uq_job_triage"),
        CheckConstraint(
            "(operation = 'scan' AND scanner_run_id IS NOT NULL AND triage_run_id IS NULL) OR "
            "(operation = 'triage' AND scanner_run_id IS NULL AND triage_run_id IS NOT NULL)",
            name="operation",
        ),
        CheckConstraint(
            "state IN ('queued','running','retry_pending','succeeded','terminal_failed')",
            name="state",
        ),
        CheckConstraint(
            "attempts = generation AND attempts >= 0 AND attempts <= max_attempts "
            "AND max_attempts BETWEEN 1 AND 5",
            name="attempts",
        ),
        CheckConstraint(
            "(state = 'running' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND heartbeat_at IS NOT NULL AND attempt_deadline IS NOT NULL) OR "
            "(state != 'running' AND lease_token IS NULL AND lease_expires_at IS NULL "
            "AND heartbeat_at IS NULL AND attempt_deadline IS NULL)",
            name="lease_shape",
        ),
        CheckConstraint("request_id ~ '^[A-Za-z0-9_-]{1,64}$'", name="request_id"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scanner_run_id: Mapped[UUID | None] = mapped_column(ForeignKey("scanner_runs.id"))
    triage_run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("triage_runs.id", use_alter=True, name="fk_jobs_triage_run_id_triage_runs")
    )
    operation: Mapped[str] = mapped_column(String(16), default="scan")
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
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


Index(
    "ix_jobs_due",
    Job.next_attempt_at,
    Job.id,
    postgresql_where=text("state IN ('queued','retry_pending')"),
)
Index("ix_jobs_expired", Job.lease_expires_at, Job.id, postgresql_where=text("state = 'running'"))


class JobAttempt(Base):
    __tablename__ = "job_attempts"
    __table_args__ = (
        UniqueConstraint("job_id", "generation", name="uq_job_attempt_generation"),
        CheckConstraint("generation > 0", name="generation"),
        CheckConstraint(
            "outcome IN ('running','succeeded','retry_pending','expired','failed')", name="outcome"
        ),
        CheckConstraint(
            "(outcome = 'running' AND completed_at IS NULL) OR "
            "(outcome != 'running' AND completed_at IS NOT NULL)",
            name="completion",
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(ForeignKey("jobs.id"))
    generation: Mapped[int] = mapped_column(Integer)
    worker_id: Mapped[UUID] = mapped_column()
    outcome: Mapped[str] = mapped_column(String(32), default="running")
    error_code: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_run_id", "id", name="uq_finding_scan_identity"),
        ForeignKeyConstraint(
            ["scan_run_id", "scanner_run_id"], ["scanner_runs.scan_run_id", "scanner_runs.id"]
        ),
        ForeignKeyConstraint(["job_id", "scanner_run_id"], ["jobs.id", "jobs.scanner_run_id"]),
        ForeignKeyConstraint(
            ["job_id", "attempt_generation"], ["job_attempts.job_id", "job_attempts.generation"]
        ),
        UniqueConstraint("scanner_run_id", "occurrence_key", name="uq_finding_occurrence"),
        CheckConstraint(
            "occurrence_key ~ '^[0-9a-f]{64}$' AND tracking_fingerprint ~ '^[0-9a-f]{64}$'",
            name="fingerprints",
        ),
        CheckConstraint("fingerprint_version = 1", name="fingerprint_version"),
        CheckConstraint(
            "severity IN ('UNKNOWN','INFO','LOW','MEDIUM','HIGH','CRITICAL')", name="severity"
        ),
        CheckConstraint("start_line > 0 AND end_line >= start_line", name="range"),
        CheckConstraint("filepath ~ '^[A-Za-z0-9_./-]{1,240}$'", name="filepath"),
        CheckConstraint(
            "jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 2048",
            name="evidence",
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scan_run_id: Mapped[UUID] = mapped_column()
    scanner_run_id: Mapped[UUID] = mapped_column()
    job_id: Mapped[UUID] = mapped_column()
    attempt_generation: Mapped[int] = mapped_column(Integer)
    occurrence_key: Mapped[str] = mapped_column(String(64))
    tracking_fingerprint: Mapped[str] = mapped_column(String(64))
    fingerprint_version: Mapped[int] = mapped_column(Integer, default=1)
    rule_id: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    original_severity: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(String(256))
    filepath: Mapped[str] = mapped_column(String(240))
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))


class ScannerInvocation(Base):
    __tablename__ = "scanner_invocations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["job_id", "generation"], ["job_attempts.job_id", "job_attempts.generation"]
        ),
        UniqueConstraint("job_id", "generation", name="uq_invocation_generation"),
        CheckConstraint("state IN ('pending','running','returned')", name="state"),
        CheckConstraint(
            "(state = 'returned' AND result IS NOT NULL) OR "
            "(state != 'returned' AND result IS NULL)",
            name="result_shape",
        ),
        CheckConstraint(
            "result IS NULL OR (jsonb_typeof(result) = 'object' "
            "AND octet_length(result::text) <= 524288)",
            name="result_bound",
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column()
    generation: Mapped[int] = mapped_column(Integer)
    lease_token: Mapped[UUID] = mapped_column()
    state: Mapped[str] = mapped_column(String(16), default="pending")
    launcher_id: Mapped[UUID | None] = mapped_column()
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class LauncherCapability(Base):
    __tablename__ = "launcher_capabilities"
    __table_args__ = (
        CheckConstraint(
            "registry_digest ~ '^[0-9a-f]{64}$' AND gate_digest ~ '^[0-9a-f]{64}$'",
            name="digests",
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True)
    registry_digest: Mapped[str] = mapped_column(String(64))
    gate_digest: Mapped[str] = mapped_column(String(64))
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


Index("ix_findings_scan_severity_id", Finding.scan_run_id, Finding.severity, Finding.id)
Index("ix_findings_scan_history", Finding.scan_run_id, Finding.created_at.desc(), Finding.id.desc())


class IdempotencyRequest(Base):
    __tablename__ = "idempotency_requests"
    __table_args__ = (
        UniqueConstraint("scope", "key", name="uq_idempotency_scope_key"),
        CheckConstraint("payload_hash ~ '^[0-9a-f]{64}$'", name="payload_hash"),
        CheckConstraint("(scan_run_id IS NULL) != (triage_run_id IS NULL)", name="one_target"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scope: Mapped[str] = mapped_column(String(64))
    key: Mapped[str] = mapped_column(String(128))
    payload_hash: Mapped[str] = mapped_column(String(64))
    scan_run_id: Mapped[UUID | None] = mapped_column(ForeignKey("scan_runs.id"))
    triage_run_id: Mapped[UUID | None] = mapped_column(ForeignKey("triage_runs.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SourceSnapshot(Base):
    __tablename__ = "source_snapshots"
    __table_args__ = (
        UniqueConstraint("id", "manifest_digest", name="uq_snapshot_manifest_identity"),
        UniqueConstraint("project_id", "id", name="uq_snapshot_project_id"),
        UniqueConstraint(
            "project_id", "content_digest", "manifest_version", name="uq_snapshot_content"
        ),
        UniqueConstraint("spool_key", name="uq_snapshot_spool_key"),
        CheckConstraint("spool_key ~ '^[A-Za-z0-9_-]{1,128}$'", name="spool_key"),
        CheckConstraint("manifest_version > 0", name="manifest_version"),
        CheckConstraint("manifest_digest ~ '^[0-9a-f]{64}$'", name="manifest_digest"),
        CheckConstraint("content_digest ~ '^[0-9a-f]{64}$'", name="content_digest"),
        CheckConstraint("inclusion_policy_digest ~ '^[0-9a-f]{64}$'", name="policy_digest"),
        CheckConstraint("byte_count >= 0 AND file_count >= 0", name="counts"),
        CheckConstraint("provenance_kind IN ('local_cli','ci_checkout')", name="provenance"),
        CheckConstraint("retention_state IN ('published','unavailable')", name="retention"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"))
    spool_key: Mapped[str] = mapped_column(String(128))
    manifest_version: Mapped[int] = mapped_column(Integer)
    manifest_digest: Mapped[str] = mapped_column(String(64))
    content_digest: Mapped[str] = mapped_column(String(64))
    inclusion_policy_digest: Mapped[str] = mapped_column(String(64))
    provenance_kind: Mapped[str] = mapped_column(String(32))
    provenance_label: Mapped[str] = mapped_column(String(200))
    byte_count: Mapped[int] = mapped_column(BigInteger)
    file_count: Mapped[int] = mapped_column(Integer)
    retention_state: Mapped[str] = mapped_column(String(32), default="published")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    acquired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        UniqueConstraint("id", "snapshot_id", name="uq_scan_snapshot_identity"),
        ForeignKeyConstraint(
            ["project_id", "snapshot_id"], ["source_snapshots.project_id", "source_snapshots.id"]
        ),
        CheckConstraint(
            "status IN ('queued','running','succeeded','partial','failed')", name="status"
        ),
        CheckConstraint("profile_digest ~ '^[0-9a-f]{64}$'", name="profile_digest"),
        CheckConstraint("char_length(profile_id) BETWEEN 1 AND 100", name="profile_id"),
        CheckConstraint(
            "(status = 'queued' AND started_at IS NULL AND completed_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL) OR "
            "(status IN ('succeeded','partial','failed') AND started_at IS NOT NULL "
            "AND completed_at IS NOT NULL)",
            name="lifecycle",
        ),
        CheckConstraint("started_at IS NULL OR started_at >= created_at", name="start_order"),
        CheckConstraint("completed_at IS NULL OR completed_at >= started_at", name="end_order"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(ForeignKey("projects.id"))
    snapshot_id: Mapped[UUID] = mapped_column()
    profile_id: Mapped[str] = mapped_column(String(100))
    profile_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


Index("ix_scan_project_history", ScanRun.project_id, ScanRun.created_at.desc(), ScanRun.id.desc())


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "(event_type = 'project.created' AND object_type = 'project') OR "
            "(event_type = 'snapshot.registered' AND object_type = 'source_snapshot') OR "
            "(event_type = 'scan.accepted' AND object_type = 'scan') OR "
            "(event_type IN ('triage.accepted','triage.send_reserved') AND "
            "object_type = 'triage') OR "
            "(event_type IN ('consent.created','consent.revoked') AND object_type = 'consent') OR "
            "(event_type = 'review.updated' AND object_type = 'review') OR "
            "(event_type IN ('job.claimed','job.succeeded','job.retry_pending',"
            "'job.failed','job.expired') AND object_type = 'job')",
            name="event_allowlist",
        ),
        CheckConstraint(
            "(actor = 'local_operator' AND component = 'api' AND event_type NOT LIKE 'job.%' "
            "AND event_type != 'triage.send_reserved') OR "
            "(actor = 'worker' AND component = 'worker' AND "
            "(event_type LIKE 'job.%' OR event_type = 'triage.send_reserved'))",
            name="actor_allowlist",
        ),
        CheckConstraint("request_id ~ '^[A-Za-z0-9_-]{1,64}$'", name="request_id"),
        CheckConstraint(
            "metadata = '{}'::jsonb OR ((metadata - 'generation') = '{}'::jsonb "
            "AND jsonb_typeof(metadata->'generation') = 'number' "
            "AND COALESCE((metadata->>'generation') ~ '^[1-9][0-9]{0,8}$', false))",
            name="metadata_allowlist",
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    event_type: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str] = mapped_column(String(32))
    object_id: Mapped[UUID] = mapped_column()
    actor: Mapped[str] = mapped_column(String(64))
    component: Mapped[str] = mapped_column(String(32))
    request_id: Mapped[str] = mapped_column(String(64))
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class HostedConsent(Base):
    __tablename__ = "hosted_consents"
    __table_args__ = (
        UniqueConstraint("operation_id", name="uq_consent_operation"),
        ForeignKeyConstraint(
            ["scan_run_id", "finding_id"], ["findings.scan_run_id", "findings.id"]
        ),
        ForeignKeyConstraint(
            ["scan_run_id", "snapshot_id"], ["scan_runs.id", "scan_runs.snapshot_id"]
        ),
        ForeignKeyConstraint(
            ["snapshot_id", "manifest_digest"],
            ["source_snapshots.id", "source_snapshots.manifest_digest"],
        ),
        CheckConstraint("config_digest ~ '^[0-9a-f]{64}$'", name="config_digest"),
        CheckConstraint(
            (
                "jsonb_typeof(data_categories) = 'array' AND "
                "octet_length(data_categories::text) <= 256"
            ),
            name="categories",
        ),
        CheckConstraint("operator = 'local_operator'", name="operator"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    operation_id: Mapped[UUID] = mapped_column()
    finding_id: Mapped[UUID] = mapped_column()
    scan_run_id: Mapped[UUID] = mapped_column()
    snapshot_id: Mapped[UUID] = mapped_column()
    manifest_digest: Mapped[str] = mapped_column(String(64))
    config_digest: Mapped[str] = mapped_column(String(64))
    data_categories: Mapped[list[str]] = mapped_column(JSONB)
    operator: Mapped[str] = mapped_column(String(32), default="local_operator")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TriageRun(Base):
    __tablename__ = "triage_runs"
    __table_args__ = (
        UniqueConstraint("id", "finding_id", name="uq_triage_finding_identity"),
        ForeignKeyConstraint(
            ["scan_run_id", "finding_id"], ["findings.scan_run_id", "findings.id"]
        ),
        ForeignKeyConstraint(
            ["scan_run_id", "snapshot_id"], ["scan_runs.id", "scan_runs.snapshot_id"]
        ),
        ForeignKeyConstraint(
            ["snapshot_id", "manifest_digest"],
            ["source_snapshots.id", "source_snapshots.manifest_digest"],
        ),
        CheckConstraint("provider IN ('deterministic-v1','openai-v1')", name="provider"),
        CheckConstraint(
            "status IN ('queued','running','succeeded','unavailable','failed')", name="status"
        ),
        CheckConstraint("config_digest ~ '^[0-9a-f]{64}$'", name="config_digest"),
        CheckConstraint("(provider = 'openai-v1') = (consent_id IS NOT NULL)", name="consent"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column()
    scan_run_id: Mapped[UUID] = mapped_column()
    snapshot_id: Mapped[UUID] = mapped_column()
    manifest_digest: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(32))
    config_digest: Mapped[str] = mapped_column(String(64))
    prompt_version: Mapped[str] = mapped_column(String(32))
    tools_version: Mapped[str] = mapped_column(String(32))
    policy_version: Mapped[str] = mapped_column(String(32))
    consent_id: Mapped[UUID | None] = mapped_column(ForeignKey("hosted_consents.id"))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TriageOutcome(Base):
    __tablename__ = "triage_outcomes"
    __table_args__ = (
        ForeignKeyConstraint(
            ["job_id", "generation"], ["job_attempts.job_id", "job_attempts.generation"]
        ),
        CheckConstraint(
            "jsonb_typeof(result) = 'object' AND octet_length(result::text) <= 16384", name="result"
        ),
        CheckConstraint(
            "jsonb_typeof(trace) = 'array' AND octet_length(trace::text) <= 4096", name="trace"
        ),
        CheckConstraint(
            "jsonb_typeof(usage) = 'object' AND octet_length(usage::text) <= 2048", name="usage"
        ),
    )
    triage_run_id: Mapped[UUID] = mapped_column(ForeignKey("triage_runs.id"), primary_key=True)
    job_id: Mapped[UUID] = mapped_column(ForeignKey("jobs.id"))
    generation: Mapped[int] = mapped_column(Integer)
    result: Mapped[dict[str, Any]] = mapped_column(JSONB)
    trace: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    usage: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ProviderCall(Base):
    __tablename__ = "triage_provider_calls"
    __table_args__ = (
        ForeignKeyConstraint(
            ["job_id", "generation"], ["job_attempts.job_id", "job_attempts.generation"]
        ),
        UniqueConstraint("job_id", "generation", "sequence", name="uq_triage_provider_sequence"),
        CheckConstraint(
            "sequence BETWEEN 1 AND 10 AND reserved_micro_usd BETWEEN 0 AND 50000", name="bounds"
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    triage_run_id: Mapped[UUID] = mapped_column(ForeignKey("triage_runs.id"))
    job_id: Mapped[UUID] = mapped_column(ForeignKey("jobs.id"))
    generation: Mapped[int] = mapped_column(Integer)
    sequence: Mapped[int] = mapped_column(Integer)
    consent_id: Mapped[UUID] = mapped_column(ForeignKey("hosted_consents.id"))
    reserved_micro_usd: Mapped[int] = mapped_column(Integer)
    reserved_tokens: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Review(Base):
    __tablename__ = "reviews"
    __table_args__ = (
        CheckConstraint("revision > 0", name="revision"),
        CheckConstraint(
            (
                "disposition IN ('confirmed','false_positive','investigate','accep"
                "ted_risk','remediation_planned')"
            ),
            name="disposition",
        ),
        CheckConstraint("char_length(note) <= 2000", name="note"),
    )
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer)
    disposition: Mapped[str] = mapped_column(String(32))
    note: Mapped[str] = mapped_column(String(2000))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ReviewRevision(Base):
    __tablename__ = "review_revisions"
    __table_args__ = (
        UniqueConstraint("finding_id", "revision", name="uq_review_revision"),
        ForeignKeyConstraint(
            ["triage_run_id", "finding_id"], ["triage_runs.id", "triage_runs.finding_id"]
        ),
        CheckConstraint("revision > 0", name="revision"),
        CheckConstraint(
            (
                "disposition IN ('confirmed','false_positive','investigate','accep"
                "ted_risk','remediation_planned')"
            ),
            name="disposition",
        ),
        CheckConstraint(
            "char_length(note) <= 2000 AND reviewer = 'local_operator'", name="content"
        ),
        CheckConstraint(
            "feedback IS NULL OR feedback IN ('agree','disagree','uncertain')", name="feedback"
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id"))
    revision: Mapped[int] = mapped_column(Integer)
    disposition: Mapped[str] = mapped_column(String(32))
    note: Mapped[str] = mapped_column(String(2000))
    reviewer: Mapped[str] = mapped_column(String(32), default="local_operator")
    triage_run_id: Mapped[UUID | None] = mapped_column()
    feedback: Mapped[str | None] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
