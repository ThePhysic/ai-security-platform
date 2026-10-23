"""Versioned real-scanner evidence and lease-fenced launcher handoff."""

import os

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003_scanner_handoff"
down_revision = "0002_orchestration"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "scanner_runs",
        sa.Column("provenance", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "findings",
        sa.Column("evidence", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "findings",
        sa.Column("synthetic", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    op.create_check_constraint(
        op.f("ck_scanner_runs_provenance"),
        "scanner_runs",
        "jsonb_typeof(provenance) = 'object' AND octet_length(provenance::text) <= 4096",
    )
    op.create_check_constraint(
        op.f("ck_findings_evidence"),
        "findings",
        "jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 2048",
    )
    op.create_table(
        "scanner_invocations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("lease_token", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("launcher_id", sa.Uuid(), nullable=True),
        sa.Column("result", JSONB(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "generation"], ["job_attempts.job_id", "job_attempts.generation"]
        ),
        sa.UniqueConstraint("job_id", "generation", name="uq_invocation_generation"),
        sa.CheckConstraint(
            "state IN ('pending','running','returned')", name=op.f("ck_scanner_invocations_state")
        ),
        sa.CheckConstraint(
            "(state = 'returned' AND result IS NOT NULL) OR "
            "(state != 'returned' AND result IS NULL)",
            name=op.f("ck_scanner_invocations_result_shape"),
        ),
        sa.CheckConstraint(
            "result IS NULL OR (jsonb_typeof(result) = 'object' "
            "AND octet_length(result::text) <= 524288)",
            name=op.f("ck_scanner_invocations_result_bound"),
        ),
    )
    op.create_table(
        "launcher_capabilities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("registry_digest", sa.String(64), nullable=False),
        sa.Column("gate_digest", sa.String(64), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "registry_digest ~ '^[0-9a-f]{64}$' AND gate_digest ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_launcher_capabilities_digests"),
        ),
    )


def downgrade():
    if os.environ.get("ASP_DISPOSABLE_TEST_DB") != "asp_phase1_test":
        raise RuntimeError("Destructive reversal requires a disposable test database")
    if op.get_bind().execute(sa.text("SELECT current_database(), current_user")).one() != (
        "asp_phase1_test",
        "asp_test",
    ):
        raise RuntimeError("Destructive reversal requires a disposable test database")
    op.drop_table("launcher_capabilities")
    op.drop_table("scanner_invocations")
    op.drop_column("findings", "synthetic")
    op.drop_column("findings", "evidence")
    op.drop_column("scanner_runs", "provenance")
