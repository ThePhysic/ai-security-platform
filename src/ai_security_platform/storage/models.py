from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
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


class SourceSnapshot(Base):
    __tablename__ = "source_snapshots"
    __table_args__ = (
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


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
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
            "event_type = 'project.created' AND object_type = 'project'", name="event_allowlist"
        ),
        CheckConstraint("actor = 'local_operator' AND component = 'api'", name="actor_allowlist"),
        CheckConstraint("request_id ~ '^[A-Za-z0-9_-]{1,64}$'", name="request_id"),
        CheckConstraint("metadata = '{}'::jsonb", name="metadata_allowlist"),
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
