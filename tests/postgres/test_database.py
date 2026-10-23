from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from ai_security_platform.api.app import create_app
from ai_security_platform.storage import repositories
from ai_security_platform.storage.base import EXPECTED_REVISION
from ai_security_platform.storage.models import AuditEvent, Project, ScanRun, SourceSnapshot
from tests.conftest import TOKEN

pytestmark = pytest.mark.postgres
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def snapshot_for(session):
    project = Project(name="metadata-fixture-only")
    session.add(project)
    session.flush()
    snapshot = SourceSnapshot(
        project_id=project.id,
        spool_key=uuid4().hex,
        manifest_version=1,
        manifest_digest="a" * 64,
        content_digest=uuid4().hex * 2,
        inclusion_policy_digest="c" * 64,
        provenance_kind="local_cli",
        provenance_label="test-only-metadata-no-source-acquired",
        byte_count=0,
        file_count=0,
        retention_state="published",
    )
    session.add(snapshot)
    session.flush()
    return project, snapshot


def test_migration_lifecycle_and_no_drift(pg_runtime):
    engine, config, _ = pg_runtime
    command.upgrade(config, "head")
    command.check(config)
    command.downgrade(config, "base")
    assert not (
        {"projects", "source_snapshots", "scan_runs", "audit_events"}
        & set(inspect(engine).get_table_names())
    )
    command.upgrade(config, "head")
    command.upgrade(config, "head")
    assert set(inspect(engine).get_table_names()) == {
        "projects",
        "source_snapshots",
        "scan_runs",
        "audit_events",
        "alembic_version",
        "scanner_runs",
        "jobs",
        "job_attempts",
        "findings",
        "idempotency_requests",
        "scanner_invocations",
        "launcher_capabilities",
        "hosted_consents",
        "triage_runs",
        "triage_outcomes",
        "triage_provider_calls",
        "reviews",
        "review_revisions",
    }


def test_project_atomic_success(pg_session):
    project = repositories.create_project(pg_session, "Persistent project", "request-1")
    assert pg_session.get(Project, project.id).name == "Persistent project"
    audit = pg_session.scalar(select(AuditEvent))
    assert audit.object_id == project.id
    assert audit.actor == "local_operator"
    assert audit.event_metadata == {}


def test_audit_failure_rolls_back_project(pg_session, monkeypatch):
    def rejected_audit(session, project_id, request_id):
        session.add(
            AuditEvent(
                event_type="project.created",
                object_type="project",
                object_id=project_id,
                actor="spoofed",
                component="api",
                request_id=request_id,
                event_metadata={},
            )
        )
        session.flush()

    monkeypatch.setattr(repositories, "append_project_audit", rejected_audit)
    with pytest.raises(IntegrityError):
        repositories.create_project(pg_session, "must-rollback", "request-2")
    assert pg_session.scalar(select(func.count()).select_from(Project)) == 0
    assert pg_session.scalar(select(func.count()).select_from(AuditEvent)) == 0


@pytest.mark.parametrize("name", ["", " ", "x" * 201, "bad\nname"])
def test_db_name_constraint(pg_session, name):
    with pytest.raises((DataError, IntegrityError)), pg_session.begin_nested():
        pg_session.add(Project(name=name))
        pg_session.flush()


@pytest.mark.parametrize(
    "field,value",
    [
        ("byte_count", -1),
        ("file_count", -1),
        ("manifest_version", 0),
        ("manifest_digest", "bad"),
        ("content_digest", "bad"),
        ("inclusion_policy_digest", "bad"),
        ("spool_key", "../escape"),
        ("provenance_kind", "remote_clone"),
        ("retention_state", "unvalidated"),
    ],
)
def test_snapshot_constraints(pg_session, field, value):
    _, snapshot = snapshot_for(pg_session)
    with pytest.raises(IntegrityError), pg_session.begin_nested():
        setattr(snapshot, field, value)
        pg_session.flush()


def test_snapshot_foreign_key_and_uniqueness(pg_session):
    _, snapshot = snapshot_for(pg_session)
    with pytest.raises(IntegrityError), pg_session.begin_nested():
        snapshot.project_id = uuid4()
        pg_session.flush()
    duplicate = SourceSnapshot(
        **{
            col.key: getattr(snapshot, col.key)
            for col in SourceSnapshot.__table__.columns
            if col.key not in {"id", "created_at", "spool_key"}
        },
        spool_key=uuid4().hex,
    )
    with pytest.raises(IntegrityError), pg_session.begin_nested():
        pg_session.add(duplicate)
        pg_session.flush()


@pytest.mark.parametrize("kind", ["wrong_project", "bad_status", "bad_digest", "bad_timeline"])
def test_scan_constraints(pg_session, kind):
    project, snapshot = snapshot_for(pg_session)
    other = Project(name="other-project")
    pg_session.add(other)
    pg_session.flush()
    scan = ScanRun(
        project_id=other.id if kind == "wrong_project" else project.id,
        snapshot_id=snapshot.id,
        profile_id="test-profile",
        profile_digest="bad" if kind == "bad_digest" else "f" * 64,
        status="unknown" if kind == "bad_status" else "queued",
        started_at=datetime.now(UTC) - timedelta(days=1) if kind == "bad_timeline" else None,
    )
    with pytest.raises(IntegrityError), pg_session.begin_nested():
        pg_session.add(scan)
        pg_session.flush()


def test_real_api_persistence_and_scan_read(pg_runtime, pg_session):
    engine, _, settings = pg_runtime
    with TestClient(create_app(settings), base_url="http://localhost:8000") as client:
        assert client.get("/ready").status_code == 200
        created = client.post("/api/v1/projects", json={"name": "API project"}, headers=AUTH)
        assert created.status_code == 201
        project_id = created.json()["id"]
        assert client.get(f"/api/v1/projects/{project_id}", headers=AUTH).status_code == 200
        project, snapshot = snapshot_for(pg_session)
        scan = ScanRun(
            project_id=project.id,
            snapshot_id=snapshot.id,
            profile_id="metadata-only",
            profile_digest="f" * 64,
            status="queued",
        )
        pg_session.add(scan)
        pg_session.commit()
        response = client.get(f"/api/v1/scan-runs/{scan.id}", headers=AUTH)
        assert response.status_code == 200 and response.json()["status"] == "queued"
        assert "findings" not in response.json()
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 1


def test_real_readiness_wrong_schema(pg_runtime):
    engine, _, settings = pg_runtime
    with engine.begin() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num='mismatch'"))
    try:
        with TestClient(create_app(settings), base_url="http://localhost:8000") as client:
            response = client.get("/ready")
            assert response.status_code == 503
            assert response.json()["code"] == "schema_unavailable"
            assert client.get("/health").status_code == 200
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE alembic_version SET version_num=:revision"),
                {"revision": EXPECTED_REVISION},
            )


def test_downgrade_refused_without_marker(pg_runtime, monkeypatch):
    engine, config, _ = pg_runtime
    monkeypatch.delenv("ASP_DISPOSABLE_TEST_DB")
    with pytest.raises(RuntimeError, match="Migration failed"):
        command.downgrade(config, "base")
    assert "projects" in inspect(engine).get_table_names()


def test_real_api_rolls_back_and_reuses_session(pg_runtime, pg_session, monkeypatch):
    _, _, settings = pg_runtime
    original = repositories.append_project_audit

    def fail_audit(*args):
        raise RuntimeError("synthetic-error-not-for-response")

    monkeypatch.setattr(repositories, "append_project_audit", fail_audit)
    with TestClient(create_app(settings), base_url="http://localhost:8000") as client:
        response = client.post("/api/v1/projects", json={"name": "rolled-back"}, headers=AUTH)
        assert response.status_code == 500
        assert "synthetic-error" not in response.text
        assert pg_session.scalar(select(func.count()).select_from(Project)) == 0
        pg_session.rollback()
        monkeypatch.setattr(repositories, "append_project_audit", original)
        assert (
            client.post("/api/v1/projects", json={"name": "works"}, headers=AUTH).status_code == 201
        )
    assert pg_session.scalar(select(func.count()).select_from(AuditEvent)) == 1
