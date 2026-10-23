"""Phase 2A intake and orchestration. Forward extension; no developer reset."""

import os

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_orchestration"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "idempotency_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scope", sa.String(length=64), nullable=False),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "payload_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_idempotency_requests_payload_hash")
        ),
        sa.ForeignKeyConstraint(
            ["scan_run_id"],
            ["scan_runs.id"],
            name=op.f("fk_idempotency_requests_scan_run_id_scan_runs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_idempotency_requests")),
        sa.UniqueConstraint("scope", "key", name="uq_idempotency_scope_key"),
    )
    op.create_table(
        "scanner_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("scanner_id", sa.String(length=32), nullable=False),
        sa.Column("adapter_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "coverage",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("winning_generation", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "jsonb_typeof(coverage) = 'object' AND octet_length(coverage::text) <= 4096",
            name=op.f("ck_scanner_runs_coverage"),
        ),
        sa.CheckConstraint(
            "scanner_id ~ '^[a-z0-9-]{1,32}$'", name=op.f("ck_scanner_runs_scanner_id")
        ),
        sa.CheckConstraint(
            "status IN ('queued','running','succeeded','failed')",
            name=op.f("ck_scanner_runs_status"),
        ),
        sa.CheckConstraint(
            "winning_generation IS NULL OR winning_generation > 0",
            name=op.f("ck_scanner_runs_winner"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_run_id"], ["scan_runs.id"], name=op.f("fk_scanner_runs_scan_run_id_scan_runs")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scanner_runs")),
        sa.UniqueConstraint("scan_run_id", "id", name="uq_scanner_scan_id"),
        sa.UniqueConstraint("scan_run_id", "scanner_id", name="uq_scanner_slot"),
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scanner_run_id", sa.Uuid(), nullable=False),
        sa.Column("operation", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("lease_token", sa.Uuid(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("worker_id", sa.Uuid(), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(state = 'running' AND lease_token IS NOT NULL AND lease_expires_at IS "
            "NOT NULL AND heartbeat_at IS NOT NULL AND attempt_deadline IS NOT "
            "NULL) OR (state != 'running' AND lease_token IS NULL AND "
            "lease_expires_at IS NULL AND heartbeat_at IS NULL AND attempt_deadline "
            "IS NULL)",
            name=op.f("ck_jobs_lease_shape"),
        ),
        sa.CheckConstraint("operation = 'scan'", name=op.f("ck_jobs_operation")),
        sa.CheckConstraint("request_id ~ '^[A-Za-z0-9_-]{1,64}$'", name=op.f("ck_jobs_request_id")),
        sa.CheckConstraint(
            "state IN ('queued','running','retry_pending','succeeded','terminal_failed')",
            name=op.f("ck_jobs_state"),
        ),
        sa.CheckConstraint(
            "attempts = generation AND attempts >= 0 AND attempts <= max_attempts "
            "AND max_attempts BETWEEN 1 AND 5",
            name=op.f("ck_jobs_attempts"),
        ),
        sa.ForeignKeyConstraint(
            ["scanner_run_id"],
            ["scanner_runs.id"],
            name=op.f("fk_jobs_scanner_run_id_scanner_runs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
        sa.UniqueConstraint("id", "scanner_run_id", name="uq_job_scanner_identity"),
        sa.UniqueConstraint("scanner_run_id", name="uq_job_scanner"),
    )
    op.create_index(
        "ix_jobs_due",
        "jobs",
        ["next_attempt_at", "id"],
        unique=False,
        postgresql_where=sa.text("state IN ('queued','retry_pending')"),
    )
    op.create_index(
        "ix_jobs_expired",
        "jobs",
        ["lease_expires_at", "id"],
        unique=False,
        postgresql_where=sa.text("state = 'running'"),
    )
    op.create_table(
        "job_attempts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.Uuid(), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(outcome = 'running' AND completed_at IS NULL) OR (outcome != "
            "'running' AND completed_at IS NOT NULL)",
            name=op.f("ck_job_attempts_completion"),
        ),
        sa.CheckConstraint(
            "outcome IN ('running','succeeded','retry_pending','expired','failed')",
            name=op.f("ck_job_attempts_outcome"),
        ),
        sa.CheckConstraint("generation > 0", name=op.f("ck_job_attempts_generation")),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], name=op.f("fk_job_attempts_job_id_jobs")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_job_attempts")),
        sa.UniqueConstraint("job_id", "generation", name="uq_job_attempt_generation"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("scanner_run_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_generation", sa.Integer(), nullable=False),
        sa.Column("occurrence_key", sa.String(length=64), nullable=False),
        sa.Column("tracking_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("fingerprint_version", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("original_severity", sa.String(length=32), nullable=False),
        sa.Column("description", sa.String(length=256), nullable=False),
        sa.Column("filepath", sa.String(length=240), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False),
        sa.Column("end_line", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "filepath ~ '^[A-Za-z0-9_./-]{1,240}$'", name=op.f("ck_findings_filepath")
        ),
        sa.CheckConstraint(
            "occurrence_key ~ '^[0-9a-f]{64}$' AND tracking_fingerprint ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_findings_fingerprints"),
        ),
        sa.CheckConstraint(
            "severity IN ('UNKNOWN','INFO','LOW','MEDIUM','HIGH','CRITICAL')",
            name=op.f("ck_findings_severity"),
        ),
        sa.CheckConstraint("fingerprint_version = 1", name=op.f("ck_findings_fingerprint_version")),
        sa.CheckConstraint(
            "start_line > 0 AND end_line >= start_line", name=op.f("ck_findings_range")
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "attempt_generation"],
            ["job_attempts.job_id", "job_attempts.generation"],
            name=op.f("fk_findings_job_id_job_attempts"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "scanner_run_id"],
            ["jobs.id", "jobs.scanner_run_id"],
            name=op.f("fk_findings_job_id_jobs"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_run_id", "scanner_run_id"],
            ["scanner_runs.scan_run_id", "scanner_runs.id"],
            name=op.f("fk_findings_scan_run_id_scanner_runs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint("scanner_run_id", "occurrence_key", name="uq_finding_occurrence"),
    )
    op.create_index(
        "ix_findings_scan_history",
        "findings",
        ["scan_run_id", sa.literal_column("created_at DESC"), sa.literal_column("id DESC")],
        unique=False,
    )
    op.create_index(
        "ix_findings_scan_severity_id", "findings", ["scan_run_id", "severity", "id"], unique=False
    )
    op.add_column(
        "source_snapshots", sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "source_snapshots", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "source_snapshots",
        sa.Column("verified", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.drop_constraint(op.f("ck_audit_events_event_allowlist"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_allowlist"),
        "audit_events",
        "(event_type = 'project.created' AND object_type = 'project') OR "
        "(event_type = 'snapshot.registered' AND object_type = "
        "'source_snapshot') OR (event_type = 'scan.accepted' AND object_type = "
        "'scan') OR (event_type IN "
        "('job.claimed','job.succeeded','job.retry_pending','job.failed','job.e"
        "xpired') AND object_type = 'job')",
    )
    op.drop_constraint(op.f("ck_audit_events_actor_allowlist"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_actor_allowlist"),
        "audit_events",
        "(actor = 'local_operator' AND component = 'api' AND event_type NOT "
        "LIKE 'job.%') OR (actor = 'worker' AND component = 'worker' AND "
        "event_type LIKE 'job.%')",
    )
    op.drop_constraint(op.f("ck_audit_events_metadata_allowlist"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_metadata_allowlist"),
        "audit_events",
        "metadata = '{}'::jsonb OR ((metadata - 'generation') = '{}'::jsonb AND "
        "jsonb_typeof(metadata->'generation') = 'number' AND "
        "COALESCE((metadata->>'generation') ~ '^[1-9][0-9]{0,8}$', false))",
    )


def downgrade() -> None:
    if os.environ.get("ASP_DISPOSABLE_TEST_DB") != "asp_phase1_test":
        raise RuntimeError("Destructive reversal requires a disposable test database")
    if op.get_bind().execute(sa.text("SELECT current_database(), current_user")).one() != (
        "asp_phase1_test",
        "asp_test",
    ):
        raise RuntimeError("Refusing destructive reversal outside the test identity")
    op.drop_column("source_snapshots", "verified")
    op.drop_column("source_snapshots", "expires_at")
    op.drop_column("source_snapshots", "acquired_at")
    op.drop_index("ix_findings_scan_severity_id", table_name="findings")
    op.drop_index("ix_findings_scan_history", table_name="findings")
    op.drop_table("findings")
    op.drop_table("job_attempts")
    op.drop_index(
        "ix_jobs_expired", table_name="jobs", postgresql_where=sa.text("state = 'running'")
    )
    op.drop_index(
        "ix_jobs_due",
        table_name="jobs",
        postgresql_where=sa.text("state IN ('queued','retry_pending')"),
    )
    op.drop_table("jobs")
    op.drop_table("scanner_runs")
    op.drop_table("idempotency_requests")
    op.execute(sa.text("DELETE FROM audit_events WHERE event_type != 'project.created'"))
    op.drop_constraint(op.f("ck_audit_events_event_allowlist"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_event_allowlist"),
        "audit_events",
        "event_type = 'project.created' AND object_type = 'project'",
    )
    op.drop_constraint(op.f("ck_audit_events_actor_allowlist"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_actor_allowlist"),
        "audit_events",
        "actor = 'local_operator' AND component = 'api'",
    )
    op.drop_constraint(op.f("ck_audit_events_metadata_allowlist"), "audit_events", type_="check")
    op.create_check_constraint(
        op.f("ck_audit_events_metadata_allowlist"), "audit_events", "metadata = '{}'::jsonb"
    )
