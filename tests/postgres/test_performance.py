"""G8 fixed-workload measurements; real PostgreSQL and independent ordinary workers."""

import json
import math
import multiprocessing as mp
import os
import platform
import time
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ai_security_platform.domain.intake import ScanSubmission, SnapshotRegistration
from ai_security_platform.jobs.controller import Controller, LeaseLost
from ai_security_platform.jobs.worker import execute
from ai_security_platform.snapshots.store import SnapshotStore
from ai_security_platform.storage.intake import accept_scan, register_snapshot
from ai_security_platform.storage.models import (
    AuditEvent,
    Finding,
    Job,
    JobAttempt,
    Project,
    ScannerRun,
    ScanRun,
)
from ai_security_platform.storage.session import build_engine, session_factory
from tests.postgres.test_orchestration import _crash_process, drain

pytestmark = [pytest.mark.postgres, pytest.mark.reliability]


def distribution(values):
    values = sorted(values)
    return {
        "n": len(values),
        "p50_ms": values[math.ceil(len(values) * 0.5) - 1],
        "p95_ms": values[math.ceil(len(values) * 0.95) - 1],
        "min_ms": values[0],
        "max_ms": values[-1],
    }


def worker(settings, spool, barrier, queue):
    import resource

    engine = build_engine(settings)
    controller = Controller(session_factory(engine), settings)
    store = SnapshotStore(Path(spool), require_readonly=False)
    completed = 0
    try:
        barrier.wait(timeout=20)
        while (lease := controller.claim()) is not None:
            execute(controller, lease, store)
            completed += 1
        usage = resource.getrusage(resource.RUSAGE_SELF)
        queue.put(
            {
                "jobs": completed,
                "max_rss_kib": usage.ru_maxrss,
                "cpu_seconds": usage.ru_utime + usage.ru_stime,
            }
        )
    finally:
        engine.dispose()


def test_fixed_200_file_workload_concurrency_and_query_plans(pg_runtime, pg_session, tmp_path):
    engine, _, settings = pg_runtime
    directory = tmp_path / "workload"
    directory.mkdir()
    for i in range(200):
        directory.joinpath(f"f{i:03}.txt").write_bytes(
            b"ASP_FAKE_FINDING\n" + (b"ASP_FAKE_CONFIG\n" if i % 20 == 0 else b"bounded data\n")
        )
    store = SnapshotStore(tmp_path / "spool", require_readonly=False)
    snapshot = store.create(directory, label="controlled-200-file-diagnostic")
    project = Project(name="Disposable G8 benchmark")
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
        "perf_snapshot",
    )
    results = []
    context = mp.get_context("spawn")
    for concurrency in (1, 2, 4):
        for cache in ("first_publication_execution", "repeated_warm"):
            scans = []
            for _ in range(12):
                with Session(engine, expire_on_commit=False) as session:
                    scans.append(
                        accept_scan(
                            session,
                            settings,
                            ScanSubmission(
                                project_id=project.id,
                                snapshot_id=registered.id,
                                profile_id="fake-v1",
                            ),
                            uuid4().hex,
                            "perf_accept",
                        ).id
                    )
            barrier, queue = context.Barrier(concurrency + 1), context.Queue()
            children = [
                context.Process(target=worker, args=(settings, str(store.root), barrier, queue))
                for _ in range(concurrency)
            ]
            spawn = time.monotonic()
            for child in children:
                child.start()
            barrier.wait(timeout=20)
            started = time.monotonic()
            measurements = [queue.get(timeout=120) for _ in children]
            for child in children:
                child.join(timeout=15)
                assert child.exitcode == 0
            elapsed = time.monotonic() - started
            with Session(engine) as session:
                parents = list(session.scalars(select(ScanRun).where(ScanRun.id.in_(scans))))
                jobs = list(
                    session.scalars(
                        select(Job).join(ScannerRun).where(ScannerRun.scan_run_id.in_(scans))
                    )
                )
                # Explicit scan membership prevents counting previous repetitions.
                attempts = session.execute(
                    select(JobAttempt, Job)
                    .join(Job, Job.id == JobAttempt.job_id)
                    .where(Job.id.in_([j.id for j in jobs]))
                ).all()
                assert len(jobs) == 24 and len(attempts) == 24
                assert all(s.status == "succeeded" for s in parents)
                assert all(j.state == "succeeded" and j.generation == 1 for j in jobs)
                assert (
                    session.scalar(
                        select(func.count())
                        .select_from(Finding)
                        .where(Finding.scan_run_id.in_(scans))
                    )
                    == 2520
                )
                waiting = [
                    (a.started_at - j.created_at).total_seconds() * 1000 for a, j in attempts
                ]
                execution = [
                    (a.completed_at - a.started_at).total_seconds() * 1000 for a, j in attempts
                ]
                lifecycle = [
                    (s.completed_at - s.created_at).total_seconds() * 1000 for s in parents
                ]
                events = session.scalar(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(
                        AuditEvent.object_id.in_([j.id for j in jobs]),
                        AuditEvent.event_type == "job.succeeded",
                    )
                )
                assert events == 24
            results.append(
                {
                    "workers": concurrency,
                    "cache_label": cache,
                    "scans": 12,
                    "jobs": 24,
                    "findings": 2520,
                    "wall_seconds": elapsed,
                    "spawn_ready_seconds": started - spawn,
                    "jobs_per_second": 24 / elapsed,
                    "queue_wait": distribution(waiting),
                    "job_execution": distribution(execution),
                    "scan_lifecycle": distribution(lifecycle),
                    "retries": 0,
                    "worker_resources": measurements,
                }
            )
    sample = scans[0]
    query_ms, history_ms = [], []
    for _ in range(30):
        with Session(engine) as session:
            start = time.perf_counter()
            list(
                session.scalars(
                    select(Finding)
                    .where(Finding.scan_run_id == sample)
                    .order_by(Finding.created_at.desc(), Finding.id.desc())
                    .limit(51)
                )
            )
            query_ms.append((time.perf_counter() - start) * 1000)
            start = time.perf_counter()
            list(
                session.scalars(
                    select(ScanRun)
                    .where(ScanRun.project_id == project.id)
                    .order_by(ScanRun.created_at.desc(), ScanRun.id.desc())
                    .limit(51)
                )
            )
            history_ms.append((time.perf_counter() - start) * 1000)
    with engine.begin() as connection:
        connection.execute(text("ANALYZE findings"))
        connection.execute(text("ANALYZE scan_runs"))
    plans = {}
    for mode in ("planner_default", "forced_sequential_diagnostic"):
        with engine.connect() as connection, connection.begin():
            if mode.startswith("forced"):
                connection.execute(text("SET LOCAL enable_indexscan=off"))
                connection.execute(text("SET LOCAL enable_bitmapscan=off"))
            plans[mode] = connection.execute(
                text(
                    "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT id,severity,filepath "
                    "FROM findings WHERE scan_run_id=:scan "
                    "ORDER BY created_at DESC,id DESC LIMIT 50"
                ),
                {"scan": sample},
            ).scalar_one()
    with engine.connect() as connection:
        plans["history"] = connection.execute(
            text(
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT id,status FROM scan_runs "
                "WHERE project_id=:project ORDER BY created_at DESC,id DESC LIMIT 50"
            ),
            {"project": project.id},
        ).scalar_one()
    result = {
        "version": "workload-1",
        "profile": "fake-v1 diagnostic; no genuine vulnerability or real scanner capacity claim",
        "files": 200,
        "bytes": sum(map(len, snapshot.files.values())),
        "total_scans": 72,
        "total_jobs": 144,
        "total_findings": 15120,
        "runs": results,
        "finding_query": distribution(query_ms),
        "history_query": distribution(history_ms),
        "plans": plans,
        "indexes_added": False,
        "cache_limit": (
            "OS/Docker caches not flushed; growing retained disposable table; "
            "cache labels are execution order only"
        ),
        "host": {"platform": platform.platform(), "cpu_count": os.cpu_count()},
        "sample_sizes": "nearest-rank percentiles; 12 scan and 24 job observations per run",
    }
    print("PERFORMANCE_REPORT=" + json.dumps(result, separators=(",", ":")), flush=True)


def test_measured_worker_kill_recovery_with_fencing(pg_runtime, pg_session, tmp_path):
    engine, _, settings = pg_runtime
    settings = settings.model_copy(
        update={
            "lease_seconds": 0.5,
            "heartbeat_seconds": 0.1,
            "attempt_seconds": 2,
            "retry_base_seconds": 0.01,
        }
    )
    directory = tmp_path / "source"
    directory.mkdir()
    directory.joinpath("inert.txt").write_bytes(b"ASP_FAKE_FINDING\n")
    store = SnapshotStore(tmp_path / "spool", require_readonly=False)
    snapshot = store.create(directory)
    project = Project(name="Disposable measured recovery")
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
        "recover_source",
    )
    parent = accept_scan(
        pg_session,
        settings,
        ScanSubmission(project_id=project.id, snapshot_id=registered.id, profile_id="fake-v1"),
        uuid4().hex,
        "recover_submit",
    )
    context = mp.get_context("spawn")
    queue = context.Queue()
    child = context.Process(
        target=_crash_process,
        args=(settings, str(store.root), "after_output", queue, "asp_phase5_recovery"),
    )
    child.start()
    lease, _ = queue.get(timeout=20)
    started = time.monotonic()
    child.terminate()
    child.join(timeout=5)
    controller = Controller(session_factory(engine), settings)
    drain(controller, store, timeout=10)
    elapsed = (time.monotonic() - started) * 1000
    assert not controller.heartbeat(lease)
    with pytest.raises(LeaseLost):
        controller.fail(lease, "execution_failed")
    with Session(engine) as session:
        assert session.get(ScanRun, parent.id).status == "succeeded"
        assert session.get(Job, lease.job_id).generation == 2
    print(
        "RECOVERY_REPORT="
        + json.dumps(
            {
                "worker_killed_after_output": True,
                "kill_to_recovered_ms": elapsed,
                "n": 1,
                "stale_write_rejected": True,
                "generation": 2,
            }
        ),
        flush=True,
    )
