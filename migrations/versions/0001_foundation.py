"""Foundation metadata only; no scan intake or jobs."""

import os

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None


def ck(table: str, name: str, expression: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(expression, name=op.f(f"ck_{table}_{name}"))


def timestamp(name: str = "created_at", *, nullable: bool = False) -> sa.Column:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        nullable=nullable,
        server_default=sa.func.now() if name == "created_at" else None,
    )


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        timestamp(),
        ck("projects", "name_length", "char_length(btrim(name)) BETWEEN 1 AND 200"),
        ck("projects", "name_controls", "name !~ '[[:cntrl:]]'"),
    )
    op.create_table(
        "source_snapshots",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("spool_key", sa.String(128), nullable=False),
        sa.Column("manifest_version", sa.Integer(), nullable=False),
        sa.Column("manifest_digest", sa.String(64), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("inclusion_policy_digest", sa.String(64), nullable=False),
        sa.Column("provenance_kind", sa.String(32), nullable=False),
        sa.Column("provenance_label", sa.String(200), nullable=False),
        sa.Column("byte_count", sa.BigInteger(), nullable=False),
        sa.Column("file_count", sa.Integer(), nullable=False),
        sa.Column("retention_state", sa.String(32), nullable=False),
        timestamp(),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name="fk_source_snapshots_project_id_projects"
        ),
        sa.UniqueConstraint("project_id", "id", name="uq_snapshot_project_id"),
        sa.UniqueConstraint(
            "project_id", "content_digest", "manifest_version", name="uq_snapshot_content"
        ),
        sa.UniqueConstraint("spool_key", name="uq_snapshot_spool_key"),
        ck("source_snapshots", "spool_key", "spool_key ~ '^[A-Za-z0-9_-]{1,128}$'"),
        ck("source_snapshots", "manifest_version", "manifest_version > 0"),
        ck("source_snapshots", "manifest_digest", "manifest_digest ~ '^[0-9a-f]{64}$'"),
        ck("source_snapshots", "content_digest", "content_digest ~ '^[0-9a-f]{64}$'"),
        ck("source_snapshots", "policy_digest", "inclusion_policy_digest ~ '^[0-9a-f]{64}$'"),
        ck("source_snapshots", "counts", "byte_count >= 0 AND file_count >= 0"),
        ck("source_snapshots", "provenance", "provenance_kind IN ('local_cli','ci_checkout')"),
        ck("source_snapshots", "retention", "retention_state IN ('published','unavailable')"),
    )
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("profile_id", sa.String(100), nullable=False),
        sa.Column("profile_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        timestamp(),
        timestamp("started_at", nullable=True),
        timestamp("completed_at", nullable=True),
        sa.ForeignKeyConstraint(
            ["project_id"], ["projects.id"], name="fk_scan_runs_project_id_projects"
        ),
        sa.ForeignKeyConstraint(
            ["project_id", "snapshot_id"],
            ["source_snapshots.project_id", "source_snapshots.id"],
            name="fk_scan_runs_project_id_source_snapshots",
        ),
        ck("scan_runs", "status", "status IN ('queued','running','succeeded','partial','failed')"),
        ck("scan_runs", "profile_digest", "profile_digest ~ '^[0-9a-f]{64}$'"),
        ck("scan_runs", "profile_id", "char_length(profile_id) BETWEEN 1 AND 100"),
        ck(
            "scan_runs",
            "lifecycle",
            "(status = 'queued' AND started_at IS NULL AND completed_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL) OR "
            "(status IN ('succeeded','partial','failed') AND started_at IS NOT NULL "
            "AND completed_at IS NOT NULL)",
        ),
        ck("scan_runs", "start_order", "started_at IS NULL OR started_at >= created_at"),
        ck("scan_runs", "end_order", "completed_at IS NULL OR completed_at >= started_at"),
    )
    op.create_index(
        "ix_scan_project_history",
        "scan_runs",
        ["project_id", sa.text("created_at DESC"), sa.text("id DESC")],
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("object_type", sa.String(32), nullable=False),
        sa.Column("object_id", sa.Uuid(), nullable=False),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("component", sa.String(32), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column(
            "metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        timestamp(),
        ck(
            "audit_events",
            "event_allowlist",
            "event_type = 'project.created' AND object_type = 'project'",
        ),
        ck("audit_events", "actor_allowlist", "actor = 'local_operator' AND component = 'api'"),
        ck("audit_events", "request_id", "request_id ~ '^[A-Za-z0-9_-]{1,64}$'"),
        ck("audit_events", "metadata_allowlist", "metadata = '{}'::jsonb"),
    )


def downgrade() -> None:
    if os.environ.get("ASP_DISPOSABLE_TEST_DB") != "asp_phase1_test":
        raise RuntimeError("Destructive reversal requires the disposable test marker")
    identity = op.get_bind().execute(sa.text("SELECT current_database(), current_user")).one()
    if identity != ("asp_phase1_test", "asp_test"):
        raise RuntimeError("Refusing destructive reversal outside the disposable test database")
    op.drop_table("audit_events")
    op.drop_index("ix_scan_project_history", table_name="scan_runs")
    op.drop_table("scan_runs")
    op.drop_table("source_snapshots")
    op.drop_table("projects")
