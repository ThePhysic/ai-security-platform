import multiprocessing as mp
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ai_security_platform.api.app import create_app
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.domain.intake import ScanSubmission, SnapshotRegistration
from ai_security_platform.snapshots.store import SnapshotStore
from ai_security_platform.storage.intake import accept_scan, register_snapshot
from ai_security_platform.storage.models import (
    AuditEvent,
    IdempotencyRequest,
    Job,
    Project,
    ScannerRun,
    ScanRun,
)
from ai_security_platform.storage.session import build_engine
from tests.conftest import TOKEN

pytestmark = pytest.mark.postgres
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def intake(pg_runtime, pg_session, tmp_path):
    _, _, settings = pg_runtime
    source = tmp_path / "source"
    source.mkdir()
    source.joinpath("example.py").write_bytes(b"ASP_FAKE_FINDING\n")
    store = SnapshotStore(tmp_path / "spool", require_readonly=False)
    snap = store.create(source)
    project = Project(name="intake-test")
    pg_session.add(project)
    pg_session.commit()
    registered = register_snapshot(
        pg_session,
        store,
        settings,
        SnapshotRegistration(
            project_id=project.id,
            snapshot_key=snap.manifest.snapshot_key,
            manifest_digest=snap.manifest_digest,
        ),
        "registration",
    )
    app = create_app(settings)
    app.state.snapshot_store = store
    body = {
        "project_id": str(project.id),
        "snapshot_id": str(registered.id),
        "profile_id": "fake-v1",
    }
    return app, store, snap, registered, body


def _submit_process(settings, body, key, barrier, queue):
    engine = build_engine(settings)
    try:
        barrier.wait(timeout=10)
        with Session(engine, expire_on_commit=False) as session:
            scan = accept_scan(
                session, settings, ScanSubmission.model_validate(body), key, "process"
            )
            queue.put((202, str(scan.id)))
    except ApiError as exc:
        queue.put((exc.status, exc.code))
    finally:
        engine.dispose()


def _race(settings, bodies, key):
    context = mp.get_context("spawn")
    barrier = context.Barrier(len(bodies))
    queue = context.Queue()
    children = [
        context.Process(target=_submit_process, args=(settings, body, key, barrier, queue))
        for body in bodies
    ]
    for process in children:
        process.start()
    results = [queue.get(timeout=20) for _ in children]
    for process in children:
        process.join(timeout=10)
        assert process.exitcode == 0
    return results


def test_process_duplicate_submissions(pg_runtime, pg_session, intake):
    _, _, settings = pg_runtime
    _, _, _, _, body = intake
    results = _race(settings, [body, body], "same-key")
    assert results[0] == results[1] and results[0][0] == 202
    assert pg_session.scalar(select(func.count()).select_from(ScanRun)) == 1
    assert pg_session.scalar(select(func.count()).select_from(ScannerRun)) == 2
    assert pg_session.scalar(select(func.count()).select_from(Job)) == 2
    assert pg_session.scalar(select(func.count()).select_from(IdempotencyRequest)) == 1


def test_process_conflict_rolls_back_loser(pg_runtime, pg_session, intake, tmp_path):
    _, _, settings = pg_runtime
    _, store, _, _, body = intake
    source = tmp_path / "other"
    source.mkdir()
    source.joinpath("other.py").write_bytes(b"ASP_FAKE_FINDING")
    snapshot = store.create(source)
    project = Project(name="another-intake")
    pg_session.add(project)
    pg_session.commit()
    registered = register_snapshot(
        pg_session,
        store,
        settings,
        SnapshotRegistration(
            project_id=project.id,
            snapshot_key=snapshot.manifest.snapshot_key,
            manifest_digest=snapshot.manifest_digest,
        ),
        "registration2",
    )
    other = dict(body, project_id=str(project.id), snapshot_id=str(registered.id))
    result = _race(settings, [body, other], "conflicting-key")
    assert sorted(status for status, _ in result) == [202, 409]
    assert (409, "idempotency_conflict") in result
    assert pg_session.scalar(select(func.count()).select_from(ScanRun)) == 1
    assert pg_session.scalar(select(func.count()).select_from(Job)) == 2


def test_http_lost_response_and_replay_before_eligibility(pg_runtime, pg_session, intake):
    app, _, _, snapshot, body = intake
    app.state.settings = app.state.settings.model_copy(update={"pending_jobs_per_project": 2})
    with TestClient(app, base_url="http://localhost:8000") as client:
        header = AUTH | {"Idempotency-Key": "lost-response"}
        original = client.post("/api/v1/scan-runs", json=body, headers=header)
        assert original.status_code == 202
        assert original.headers["location"] == original.json()["status_url"]
        assert (
            client.post(
                "/api/v1/scan-runs", json=body, headers=AUTH | {"Idempotency-Key": "full"}
            ).status_code
            == 429
        )
        snapshot.retention_state = "unavailable"
        snapshot.expires_at = datetime.now(UTC) - timedelta(days=1)
        pg_session.commit()
        replay = client.post("/api/v1/scan-runs", json=body, headers=header)
        assert replay.status_code == 202 and replay.json()["id"] == original.json()["id"]
        conflict = client.post(
            "/api/v1/scan-runs", json=dict(body, project_id=str(uuid4())), headers=header
        )
        assert conflict.status_code == 409
        assert client.get(original.headers["location"], headers=AUTH).json()["scanner_runs"]
    count = pg_session.scalar(
        select(func.count()).select_from(AuditEvent).where(AuditEvent.event_type == "scan.accepted")
    )
    assert count == 1


def test_registration_identity_auth_and_mismatch(pg_session, intake):
    app, _, snap, registered, body = intake
    request = {
        "project_id": body["project_id"],
        "snapshot_key": snap.manifest.snapshot_key,
        "manifest_digest": snap.manifest_digest,
    }
    with TestClient(app, base_url="http://localhost:8000") as client:
        assert client.post("/api/v1/source-snapshots", json=request).status_code == 401
        same = client.post("/api/v1/source-snapshots", headers=AUTH, json=request)
        assert same.status_code == 201 and same.json()["id"] == str(registered.id)
        assert (
            client.post(
                "/api/v1/source-snapshots",
                headers=AUTH,
                json=dict(request, manifest_digest="f" * 64),
            ).status_code
            == 409
        )
        assert (
            client.post(
                "/api/v1/source-snapshots",
                headers=AUTH,
                json=dict(request, snapshot_key="../escape"),
            ).status_code
            == 422
        )
        invalid = client.post(
            "/api/v1/source-snapshots", headers=AUTH, json=dict(request, snapshot_key=uuid4().hex)
        )
        assert invalid.status_code == 409
        assert "spool" not in same.text


def test_atomic_acceptance_failure_leaves_no_orphans(pg_session, intake, monkeypatch):
    import ai_security_platform.storage.intake as module

    app, _, _, _, body = intake

    def failure(*args, **kwargs):
        raise RuntimeError("synthetic-intake-failure")

    monkeypatch.setattr(module, "audit", failure)
    with TestClient(app, base_url="http://localhost:8000") as client:
        response = client.post(
            "/api/v1/scan-runs", headers=AUTH | {"Idempotency-Key": "rollback"}, json=body
        )
        assert response.status_code == 500 and "synthetic" not in response.text
    assert pg_session.scalar(select(func.count()).select_from(ScanRun)) == 0
    assert pg_session.scalar(select(func.count()).select_from(Job)) == 0
    assert pg_session.scalar(select(func.count()).select_from(IdempotencyRequest)) == 0


def test_scan_history_keyset_binding_and_limits(pg_runtime, pg_session, intake):
    app, _, _, _, body = intake
    with TestClient(app, base_url="http://localhost:8000") as client:
        ids = []
        for number in range(5):
            response = client.post(
                "/api/v1/scan-runs", json=body, headers=AUTH | {"Idempotency-Key": f"page-{number}"}
            )
            assert response.status_code == 202
            ids.append(response.json()["id"])
        path = "/api/v1/scan-runs?project=" + body["project_id"] + "&limit=2"
        page = client.get(path, headers=AUTH).json()
        seen = [item["id"] for item in page["items"]]
        cursor = page["next_cursor"]
        assert cursor
        newer = client.post(
            "/api/v1/scan-runs", json=body, headers=AUTH | {"Idempotency-Key": "page-new"}
        )
        assert client.get(path + "&status=queued&cursor=" + cursor, headers=AUTH).status_code == 400
        assert client.get(path + "&cursor=" + cursor + "tampered", headers=AUTH).status_code == 400
        while cursor:
            page = client.get(path + "&cursor=" + cursor, headers=AUTH).json()
            seen += [item["id"] for item in page["items"]]
            cursor = page["next_cursor"]
        assert set(seen) == set(ids) and len(seen) == 5
        assert newer.json()["id"] not in seen
        assert client.get(path + "&limit=101", headers=AUTH).status_code == 422
        empty = client.get(f"/api/v1/scan-runs/{UUID(ids[0])}/findings", headers=AUTH)
        assert empty.json() == {"items": [], "next_cursor": None}
