"""Real PostgreSQL and spawned processes: no mock lease/recovery substitutes."""

import json
import multiprocessing as mp
import time
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select, text
from sqlalchemy.orm import Session

from ai_security_platform.domain.intake import ScanSubmission
from ai_security_platform.jobs.controller import Controller, LeaseLost
from ai_security_platform.jobs.worker import execute
from ai_security_platform.scanners.fake import scan
from ai_security_platform.snapshots.store import SnapshotStore
from ai_security_platform.storage.intake import accept_scan
from ai_security_platform.storage.models import (
    AuditEvent,
    Finding,
    Job,
    JobAttempt,
    ScannerRun,
    ScanRun,
)
from ai_security_platform.storage.session import build_engine, session_factory
from tests.postgres.test_intake import AUTH
from tests.postgres.test_intake import intake as intake_fixture

intake = intake_fixture

pytestmark = [pytest.mark.postgres, pytest.mark.orchestration]


@pytest.fixture
def execution(pg_runtime, pg_session, intake):  # noqa: F811
    engine, _, settings = pg_runtime
    _, store, _, _, body = intake
    settings = settings.model_copy(
        update={
            "lease_seconds": 0.4,
            "heartbeat_seconds": 0.08,
            "attempt_seconds": 1.2,
            "retry_base_seconds": 0.01,
        }
    )
    parent = accept_scan(
        pg_session, settings, ScanSubmission.model_validate(body), "execution", "test_execution"
    )
    # Always crash the scanner that inserts a finding, so pre-commit tests
    # exercise actual finding inserts rather than an empty result.
    with Session(engine) as session, session.begin():
        pattern_job = session.scalars(
            select(Job).join(ScannerRun).where(ScannerRun.scanner_id == "fake-patterns")
        ).one()
        pattern_job.next_attempt_at = Controller.now(session) - timedelta(seconds=1)
    return Controller(session_factory(engine), settings), store, parent


def drain(controller, store, timeout=8):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        controller.recover_one()
        lease = controller.claim()
        if lease:
            execute(controller, lease, store)
            continue
        with controller.factory() as session:
            pending = session.scalar(
                select(func.count())
                .select_from(Job)
                .where(Job.state.in_(["queued", "running", "retry_pending"]))
            )
        if not pending:
            return
        time.sleep(0.03)
    raise AssertionError("Execution did not reach bounded terminal state")


def _claim_process(settings, barrier, queue):
    engine = build_engine(settings)
    try:
        controller = Controller(session_factory(engine), settings)
        barrier.wait(timeout=10)
        lease = controller.claim()
        queue.put(lease)
    finally:
        engine.dispose()


def _complete_process(settings, spool, barrier, queue):
    engine = build_engine(settings)
    try:
        controller = Controller(session_factory(engine), settings)
        lease = controller.claim()
        store = SnapshotStore(Path(spool), require_readonly=False)
        source = store.verify(lease.snapshot_key, lease.manifest_digest)
        result = scan(lease.scanner_id, source)
        barrier.wait(timeout=10)
        controller.finish(lease, result, source)
        queue.put(lease.scanner_id)
    finally:
        engine.dispose()


def test_concurrent_scanner_completions_aggregate_under_parent_lock(pg_session, execution):
    controller, store, parent = execution
    settings = controller.settings.model_copy(update={"lease_seconds": 3, "attempt_seconds": 5})
    context = mp.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    children = [
        context.Process(target=_complete_process, args=(settings, str(store.root), barrier, queue))
        for _ in range(2)
    ]
    for process in children:
        process.start()
    completed = [queue.get(timeout=15) for _ in children]
    for process in children:
        process.join(timeout=10)
        assert process.exitcode == 0
    assert set(completed) == {"fake-patterns", "fake-config"}
    pg_session.expire_all()
    assert pg_session.get(ScanRun, parent.id).status == "succeeded"
    assert pg_session.scalar(select(func.count()).select_from(Finding)) == 1


def test_four_process_skip_locked_claims(pg_session, execution):
    controller, store, parent = execution
    context = mp.get_context("spawn")
    barrier, queue = context.Barrier(4), context.Queue()
    children = [
        context.Process(target=_claim_process, args=(controller.settings, barrier, queue))
        for _ in range(4)
    ]
    for process in children:
        process.start()
    leases = [queue.get(timeout=15) for _ in children]
    for process in children:
        process.join(timeout=10)
        assert process.exitcode == 0
    claimed = [lease for lease in leases if lease]
    assert len(claimed) == 2
    assert len({lease.job_id for lease in claimed}) == 2
    assert len({lease.token for lease in claimed}) == 2
    assert all(lease.generation == 1 for lease in claimed)
    drain(controller, store)
    pg_session.expire_all()
    assert pg_session.get(ScanRun, parent.id).status == "succeeded"


def test_stale_generation_cannot_renew_publish_findings_status_or_audit(pg_session, execution):
    controller, store, parent = execution
    lease = controller.claim()
    source = store.verify(lease.snapshot_key, lease.manifest_digest)
    result = scan(lease.scanner_id, source)
    assert not controller.heartbeat(replace(lease, token=uuid4()))
    time.sleep(0.45)
    assert not controller.heartbeat(lease)  # expired leases cannot be revived
    with pytest.raises(LeaseLost):
        controller.finish(lease, result, source)
    with pytest.raises(LeaseLost):
        controller.fail(lease, "execution_failed")
    assert controller.recover_one()
    drain(controller, store)
    before = [
        pg_session.scalar(select(func.count()).select_from(model))
        for model in (Finding, AuditEvent)
    ]
    with pytest.raises(LeaseLost):
        controller.finish(lease, result, source)
    assert not controller.heartbeat(lease)
    # Uniqueness is not the fence: even entirely new occurrence keys must fail.
    assert result.findings
    different = result.model_copy(
        update={"findings": [result.findings[0].model_copy(update={"occurrence_key": "e" * 64})]}
    )
    with pytest.raises(LeaseLost):
        controller.finish(lease, different, source)
    assert before == [
        pg_session.scalar(select(func.count()).select_from(model))
        for model in (Finding, AuditEvent)
    ]
    pg_session.expire_all()
    assert pg_session.get(ScanRun, parent.id).status == "succeeded"
    assert pg_session.get(Job, lease.job_id).generation == 2


def test_heartbeat_independent_and_hard_deadline(pg_session, execution):
    controller, _, _ = execution
    lease = controller.claim()
    for _ in range(6):
        time.sleep(0.11)
        assert controller.heartbeat(lease)
    with controller.factory() as session:
        job = session.get(Job, lease.job_id)
        assert job.lease_expires_at <= job.attempt_deadline
        assert job.generation == 1
    time.sleep(0.6)
    assert not controller.heartbeat(lease)
    assert controller.recover_one()


def test_independent_heartbeat_during_adapter_execution(pg_session, execution, monkeypatch):
    from ai_security_platform.jobs import worker

    controller, store, _ = execution
    lease = controller.claim()
    original = worker.scan

    def slow(scanner_id, source):
        time.sleep(0.7)  # longer than a lease; heartbeat must use another connection
        return original(scanner_id, source)

    monkeypatch.setattr(worker, "scan", slow)
    worker.execute(controller, lease, store)
    pg_session.expire_all()
    job = pg_session.get(Job, lease.job_id)
    assert job.state == "succeeded" and job.generation == 1


def test_repeated_expiry_reaches_terminal_failure(pg_session, execution):
    controller, _, parent = execution
    for _ in range(6):
        lease = None
        until = time.monotonic() + 2
        while lease is None and time.monotonic() < until:
            lease = controller.claim()
            if lease is None:
                time.sleep(0.03)
        assert lease is not None
        time.sleep(0.45)
        assert controller.recover_one()
    assert controller.claim() is None
    pg_session.expire_all()
    assert pg_session.get(ScanRun, parent.id).status == "failed"
    assert list(pg_session.scalars(select(Job.state))) == ["terminal_failed", "terminal_failed"]
    assert pg_session.scalar(select(func.count()).select_from(JobAttempt)) == 6


def test_bounded_retries_and_partial_results(pg_session, execution):
    controller, store, parent = execution
    first = controller.claim()
    source = store.verify(first.snapshot_key, first.manifest_digest)
    controller.finish(first, scan(first.scanner_id, source), source)
    for attempt in range(1, 4):
        lease = None
        until = time.monotonic() + 2
        while lease is None and time.monotonic() < until:
            lease = controller.claim()
            if lease is None:
                time.sleep(0.03)
        assert lease.generation == attempt
        controller.fail(lease, "execution_failed")
    assert controller.claim() is None
    pg_session.expire_all()
    assert pg_session.get(ScanRun, parent.id).status == "partial"
    assert sorted(pg_session.scalars(select(ScannerRun.status))) == ["failed", "succeeded"]
    assert list(
        pg_session.scalars(
            select(JobAttempt.outcome)
            .where(JobAttempt.job_id == lease.job_id)
            .order_by(JobAttempt.generation)
        )
    ) == ["retry_pending", "retry_pending", "failed"]
    assert pg_session.scalar(select(func.count()).select_from(Finding)) in {0, 1}


def test_atomic_publication_rollback_and_invalid_output(pg_session, execution):
    controller, store, _ = execution
    lease = controller.claim()
    source = store.verify(lease.snapshot_key, lease.manifest_digest)
    result = scan(lease.scanner_id, source)

    def interrupt(_):
        raise RuntimeError("synthetic_transaction_failure")

    with pytest.raises(RuntimeError):
        controller.finish(lease, result, source, interrupt)
    assert pg_session.scalar(select(func.count()).select_from(Finding)) == 0
    assert (
        pg_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.event_type == "job.succeeded")
        )
        == 0
    )
    invalid = result.model_copy(update={"files_scanned": 511})
    with pytest.raises(ValueError):
        controller.finish(lease, invalid, source)
    controller.finish(lease, result, source)


def test_nonempty_findings_pagination_and_query_bounds(
    pg_runtime,
    pg_session,
    intake,
    tmp_path,  # noqa: F811
):
    from fastapi.testclient import TestClient

    from ai_security_platform.domain.intake import SnapshotRegistration
    from ai_security_platform.storage.intake import register_snapshot

    app, store, _, _, body = intake
    engine, _, settings = pg_runtime
    source = tmp_path / "pagination"
    source.mkdir()
    source.joinpath("many.py").write_bytes(b"ASP_FAKE_FINDING\n" * 7 + b"ASP_FAKE_CONFIG\n")
    snap = store.create(source)
    snapshot = register_snapshot(
        pg_session,
        store,
        settings,
        SnapshotRegistration(
            project_id=body["project_id"],
            snapshot_key=snap.manifest.snapshot_key,
            manifest_digest=snap.manifest_digest,
        ),
        "pagination_snapshot",
    )
    parent = accept_scan(
        pg_session,
        settings,
        ScanSubmission(
            project_id=body["project_id"],
            snapshot_id=snapshot.id,
            profile_id="fake-v1",
        ),
        "findings-pages",
        "pagination_accept",
    )
    drain(Controller(session_factory(engine), settings), store)
    queries = []

    def capture(_, __, statement, ___, ____, _____):
        queries.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    app.state.engine.dispose()
    # Capture on the app's own engine, with no SQL parameters in the evidence.
    event.listen(app.state.engine, "before_cursor_execute", capture)
    try:
        with TestClient(app, base_url="http://localhost:8000") as client:
            base = f"/api/v1/scan-runs/{parent.id}/findings"
            response = client.get(base, headers=AUTH, params={"limit": 3, "severity": "MEDIUM"})
            assert response.status_code == 200
            cursor = response.json()["next_cursor"]
            assert (
                client.get(
                    base,
                    headers=AUTH,
                    params={
                        "cursor": cursor,
                        "severity": "HIGH",
                    },
                ).status_code
                == 400
            )
            items = response.json()["items"]
            while cursor:
                response = client.get(
                    base,
                    headers=AUTH,
                    params={
                        "limit": 3,
                        "severity": "MEDIUM",
                        "cursor": cursor,
                    },
                )
                assert response.status_code == 200
                items.extend(response.json()["items"])
                cursor = response.json()["next_cursor"]
            assert len(items) == len({item["id"] for item in items}) == 8
            filtered = client.get(base, headers=AUTH, params={"scanner": "fake-config"})
            assert len(filtered.json()["items"]) == 1
            assert client.get(base, headers=AUTH, params={"limit": 101}).status_code == 422
        finding_queries = [q for q in queries if "FROM findings" in q]
        assert finding_queries and all(
            "LIMIT" in q.upper() and "OFFSET" not in q.upper() for q in finding_queries
        )
    finally:
        event.remove(engine, "before_cursor_execute", capture)
        event.remove(app.state.engine, "before_cursor_execute", capture)


def _crash_process(settings, spool, point, queue, application):
    engine = build_engine(settings)

    @event.listens_for(engine, "connect")
    def identify(connection, _):
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('application_name', %s, false)", (application,))

    controller = Controller(session_factory(engine), settings)
    store = SnapshotStore(Path(spool), require_readonly=False)
    lease = controller.claim()

    def checkpoint(stage):
        if stage == point or (stage == "after_findings" and point == "database_disconnect"):
            queue.put((lease, stage))
            # The parent forcibly terminates this process or its DB connection.
            time.sleep(30)

    checkpoint("after_claim")
    source = store.verify(lease.snapshot_key, lease.manifest_digest)
    result = scan(lease.scanner_id, source)
    checkpoint("after_output")
    controller.finish(lease, result, source, checkpoint)


@pytest.mark.parametrize("iteration", range(5))
@pytest.mark.parametrize(
    "point",
    ["after_claim", "after_output", "after_findings", "after_commit", "database_disconnect"],
)
def test_25_process_crash_retry_experiments(pg_runtime, pg_session, execution, point, iteration):
    controller, store, parent = execution
    context = mp.get_context("spawn")
    queue = context.Queue()
    application = "asp_crash_" + uuid4().hex
    process = context.Process(
        target=_crash_process,
        args=(controller.settings, str(store.root), point, queue, application),
    )
    process.start()
    lease, _ = queue.get(timeout=15)
    if point == "database_disconnect":
        engine, _, _ = pg_runtime
        with engine.begin() as connection:
            terminated = (
                connection.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE application_name = :application AND pid <> pg_backend_pid()"
                    ),
                    {"application": application},
                )
                .scalars()
                .all()
            )
            assert terminated and all(terminated)
    process.terminate()
    process.join(timeout=5)
    assert process.exitcode is not None and process.exitcode != 0
    drain(controller, store)
    pg_session.expire_all()
    job = pg_session.get(Job, lease.job_id)
    assert job.state == "succeeded"
    assert job.generation == (1 if point == "after_commit" else 2)
    assert pg_session.get(ScanRun, parent.id).status == "succeeded"
    assert (
        pg_session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.object_id == job.id, AuditEvent.event_type == "job.succeeded")
        )
        == 1
    )
    assert pg_session.scalar(select(func.count()).select_from(Finding)) == 1
    stale_source = store.verify(lease.snapshot_key, lease.manifest_digest)
    with pytest.raises(LeaseLost):
        controller.finish(lease, scan(lease.scanner_id, stale_source), stale_source)
    assert not controller.heartbeat(lease)
    # Persist each independent result in the container output for the completion report.
    print(
        json.dumps(
            {
                "experiment": iteration + 1,
                "point": point,
                "job_generation": job.generation,
                "scan_status": "succeeded",
                "completion_events": 1,
                "findings": 1,
                "stale_publication": "rejected",
            }
        )
    )
