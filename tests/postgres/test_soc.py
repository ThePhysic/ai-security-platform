"""Optional-schema tests require real guarded PostgreSQL and spawned processes."""

import json
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import time
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from ai_security_platform.api.app import create_app
from ai_security_platform.config import Settings
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.jobs.controller import LeaseLost
from ai_security_platform.soc.contracts import DatasetCreate, Ingest, ReviewWrite
from ai_security_platform.soc.controller import SocController
from ai_security_platform.soc.models import (
    AnalystFeedback,
    Audit,
    CorrelationRun,
    Investigation,
    Job,
    SecurityEvent,
)
from ai_security_platform.soc.scenarios import scenario
from ai_security_platform.soc.store import create_dataset, ingest, review
from ai_security_platform.soc.worker import execute
from ai_security_platform.storage.repositories import create_project
from ai_security_platform.storage.session import build_engine, session_factory
from tests.conftest import TOKEN

pytestmark = pytest.mark.postgres
CTX = mp.get_context("spawn")


@pytest.fixture
def soc(pg_runtime, monkeypatch):
    engine, _, settings = pg_runtime
    monkeypatch.setenv("ASP_SOC_ENABLED", "true")
    config = Config("src/ai_security_platform/soc/alembic.ini")
    command.upgrade(config, "head")
    factory = session_factory(engine)
    with factory.begin() as session:
        session.execute(text("TRUNCATE soc.datasets CASCADE"))
        session.execute(text("TRUNCATE soc.audit_events"))
    yield factory, settings.model_copy(update={"soc_enabled": True}), config


def accept(factory, name="auth-burst", key="initial", dataset=None, body=None):
    dataset = dataset or uuid4()
    with factory() as session:
        create_dataset(session, DatasetCreate(id=dataset, label="synthetic-test"), "soc-test")
        accepted = ingest(session, dataset, body or scenario(name), key, "soc-test")
    return dataset, UUID(accepted["id"])


@pytest.mark.parametrize(
    "name,count,state",
    [
        ("auth-burst", 1, "matched"),
        ("session-grant", 1, "matched"),
        ("clean", 0, None),
        ("incomplete", 1, "incomplete"),
    ],
)
def test_actual_persistence_and_evidence(soc, name, count, state):
    factory, settings, _ = soc
    dataset, run_id = accept(factory, name)
    controller = SocController(factory, settings)
    lease = controller.claim()
    assert lease.run_id == run_id
    execute(controller, lease)
    with factory() as session:
        run = session.get(CorrelationRun, run_id)
        assert run.status == "succeeded"
        rows = list(session.scalars(select(Investigation)))
        assert len(rows) == count
        if count:
            assert rows[0].evidence_state == state
            for evidence in rows[0].evidence:
                event = session.get(SecurityEvent, UUID(evidence["id"]))
                assert event.dataset_id == dataset
                assert event.payload_digest == evidence["payload_digest"]
                assert event.occurred_at.isoformat() == evidence["occurred_at"]


def test_replay_conflict_atomicity_and_late_events(soc):
    factory, settings, _ = soc
    full = scenario("session-grant")
    late = Ingest(events=[full.events[0]])
    first = Ingest(events=[full.events[1]])
    dataset, run_id = accept(factory, body=first)
    controller = SocController(factory, settings)
    lease = controller.claim()
    execute(controller, lease)
    with factory() as session:
        saved = session.scalar(select(Investigation)).evidence
        session.rollback()
        replay = ingest(session, dataset, first, "initial", "replay")
        assert UUID(replay["id"]) == run_id
        after = ingest(session, dataset, late, "late", "late")
        assert after["out_of_order"] == after["accepted"] == 1
        assert after["delayed"] == 1
        with pytest.raises(ApiError) as error:
            ingest(session, dataset, late, "initial", "conflict")
        assert error.value.status == 409
        conflict = full.events[1].model_copy(update={"action": "permission_removed"})
        with pytest.raises(ApiError):
            ingest(session, dataset, Ingest(events=[conflict]), "different", "conflict")
    execute(controller, controller.claim())
    with factory() as session:
        old = session.scalar(select(Investigation).where(Investigation.run_id == run_id))
        assert old.evidence == saved and old.evidence_state == "incomplete"
        latest = session.scalar(select(Investigation).where(Investigation.run_id != run_id))
        assert latest.evidence_state == "matched"
        assert latest.tracking_id == old.tracking_id
        assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 2
        assert session.scalar(select(func.count()).select_from(Job)) == 2


def ingest_child(url, dataset, action, output):
    engine = build_engine(Settings(_env_file=None, database_url=url, api_token=TOKEN))
    with session_factory(engine)() as session:
        try:
            body = scenario("clean")
            if action == "conflict":
                body = Ingest(
                    events=[body.events[0].model_copy(update={"action": "access_denied"})]
                )
            value = ingest(session, dataset, body, "same", "concurrent")
            output.put((202, value["id"]))
        except ApiError as error:
            output.put((error.status, error.code))
    engine.dispose()


def test_concurrent_ingestion_processes(soc):
    factory, settings, _ = soc
    dataset = uuid4()
    with factory() as session:
        create_dataset(session, DatasetCreate(id=dataset), "race")
    output = CTX.Queue()
    processes = [
        CTX.Process(
            target=ingest_child,
            args=(settings.database_url.get_secret_value(), dataset, kind, output),
        )
        for kind in ["identical", "identical", "conflict"]
    ]
    for process in processes:
        process.start()
    results = [output.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    assert sorted(item[0] for item in results) in ([202, 202, 409], [202, 409, 409])
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(Job)) == 1
        assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 1


def worker_child(values, output, pause):
    settings = Settings(_env_file=None, **values)
    engine = build_engine(settings)
    controller = SocController(session_factory(engine), settings)
    lease = controller.claim()
    output.put(lease)
    if lease and pause:
        result = controller.compute(lease)

        def checkpoint(where):
            if where == pause:
                output.put(where)
                time.sleep(60)

        controller.finish(lease, result, checkpoint)
    engine.dispose()


@pytest.mark.parametrize("pause", ["after_investigations", "after_commit"])
def test_killed_worker_recovery_and_stale_fencing(soc, pause):
    factory, settings, _ = soc
    dataset, run_id = accept(factory)
    settings = settings.model_copy(
        update={
            "lease_seconds": 0.5,
            "heartbeat_seconds": 0.1,
            "attempt_seconds": 2,
            "retry_base_seconds": 0.01,
        }
    )
    values = {
        "database_url": settings.database_url.get_secret_value(),
        "api_token": TOKEN,
        "soc_enabled": True,
        "lease_seconds": 0.5,
        "heartbeat_seconds": 0.1,
        "attempt_seconds": 2,
        "retry_base_seconds": 0.01,
    }
    output = CTX.Queue()
    process = CTX.Process(target=worker_child, args=(values, output, pause))
    process.start()
    stale = output.get(timeout=30)
    assert output.get(timeout=30) == pause
    process.terminate()
    process.join(10)
    assert not process.is_alive()
    controller = SocController(factory, settings)
    time.sleep(0.6)
    recovered = controller.recover_one()
    if pause == "after_investigations":
        assert recovered
        time.sleep(0.05)
        lease = controller.claim()
        assert lease.generation == stale.generation + 1 and lease.token != stale.token
        assert not controller.heartbeat(stale)
        with pytest.raises(LeaseLost):
            controller.finish(stale, controller.compute(stale))
        with pytest.raises(LeaseLost):
            controller.fail(stale)
        execute(controller, lease)
    else:
        assert not recovered and controller.claim() is None
    with factory() as session:
        assert session.get(CorrelationRun, run_id).status == "succeeded"
        assert session.scalar(select(func.count()).select_from(Investigation)) == 1
        assert (
            session.scalar(
                select(func.count()).select_from(Audit).where(Audit.event == "job.succeeded")
            )
            == 1
        )
    print(
        "SOC_RECOVERY="
        + json.dumps({"checkpoint": pause, "recovered": recovered, "authoritative_completions": 1})
    )


def test_concurrent_claim_and_retry_exhaustion(soc):
    factory, settings, _ = soc
    accept(factory)
    values = {
        "database_url": settings.database_url.get_secret_value(),
        "api_token": TOKEN,
        "soc_enabled": True,
    }
    output = CTX.Queue()
    processes = [CTX.Process(target=worker_child, args=(values, output, None)) for _ in range(4)]
    for process in processes:
        process.start()
    leases = [output.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    lease = next(item for item in leases if item)
    assert sum(item is not None for item in leases) == 1
    controller = SocController(factory, settings.model_copy(update={"retry_base_seconds": 0.01}))
    for attempt in range(3):
        assert controller.heartbeat(lease)
        controller.fail(lease)
        time.sleep(0.1)
        lease = controller.claim()
        if attempt < 2:
            assert lease.generation == attempt + 2
        else:
            assert lease is None
    with factory() as session:
        assert session.scalar(select(Job)).state == "terminal_failed"
        assert session.scalar(select(CorrelationRun)).status == "failed"


def review_child(url, identifier, output):
    engine = build_engine(Settings(_env_file=None, database_url=url, api_token=TOKEN))
    with session_factory(engine)() as session:
        try:
            review(
                session,
                identifier,
                ReviewWrite(
                    expected_revision=0, disposition="investigate", note="SYNTHETIC_SECRET_hidden"
                ),
                "review-race",
            )
            output.put(200)
        except ApiError as error:
            output.put(error.status)
    engine.dispose()


def test_review_concurrency_and_immutable_history(soc):
    factory, settings, _ = soc
    accept(factory)
    controller = SocController(factory, settings)
    execute(controller, controller.claim())
    with factory() as session:
        identifier = session.scalar(select(Investigation.id))
    output = CTX.Queue()
    processes = [
        CTX.Process(
            target=review_child, args=(settings.database_url.get_secret_value(), identifier, output)
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    assert sorted(output.get(timeout=30) for _ in processes) == [200, 409]
    for process in processes:
        process.join(10)
        assert process.exitcode == 0
    with factory() as session:
        assert session.scalar(select(AnalystFeedback)).revision == 1
        assert "SYNTHETIC_SECRET_hidden" not in session.scalar(select(AnalystFeedback)).note
        for table in ["security_events", "analyst_feedback", "audit_events"]:
            with pytest.raises(DBAPIError):
                session.execute(text(f"DELETE FROM soc.{table}"))
                session.commit()
            session.rollback()


def test_atomic_publication_bad_output_and_database_interruption(soc):
    factory, settings, _ = soc
    accept(factory)
    controller = SocController(factory, settings)
    lease = controller.claim()
    result = controller.compute(lease)
    bad = [dict(result[0], evidence=[])]
    with pytest.raises(ValueError):
        controller.finish(lease, bad)

    def disconnect(where):
        if where == "after_investigations":
            with factory.begin() as other:
                # Kill only the connection holding this explicitly disposable SOC job lock.
                pids = other.scalars(
                    text(
                        "SELECT pid FROM pg_stat_activity WHERE datname=current_database() "
                        "AND pid != pg_backend_pid() AND state='idle in transaction' "
                        "AND query LIKE '%soc.investigations%'"
                    )
                ).all()
                assert len(pids) == 1
                assert other.scalar(text("SELECT pg_terminate_backend(:pid)"), {"pid": pids[0]})

    with pytest.raises(DBAPIError):
        controller.finish(lease, result, disconnect)
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(Investigation)) == 0
        assert (
            session.scalar(
                select(func.count()).select_from(Audit).where(Audit.event == "job.succeeded")
            )
            == 0
        )
    # The failed transaction did not consume ownership; retry publication is safe.
    controller.finish(lease, result)
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(Investigation)) == 1


def test_indexed_history_and_quota(soc):
    factory, settings, _ = soc
    dataset = None
    base = scenario("clean").events[0]
    for batch in range(50):
        events = [base.model_copy(update={"event_id": f"event-{batch}-{i}"}) for i in range(20)]
        dataset, _ = accept(
            factory, dataset=dataset, key=f"batch-{batch}", body=Ingest(events=events)
        )
    with factory.begin() as session:
        session.execute(text("ANALYZE soc.security_events"))
        plan = session.execute(
            text(
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT id,ingested_at "
                "FROM soc.security_events WHERE dataset_id=:dataset "
                "ORDER BY ingested_at DESC,id DESC LIMIT 20"
            ),
            {"dataset": dataset},
        ).scalar()
        assert "ix_soc_events_history" in json.dumps(plan)
        print("SOC_QUERY_PLAN=" + json.dumps({"rows": 1000, "plan": plan}))
    with factory() as session:
        with pytest.raises(ApiError) as error:
            ingest(
                session,
                dataset,
                Ingest(events=[base.model_copy(update={"event_id": "overflow"})]),
                "overflow",
                "quota",
            )
        assert error.value.status == 429
        assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 1000


def appsec_fingerprints(session):
    from ai_security_platform.storage.base import Base

    return {
        table: session.scalar(
            text(
                f"SELECT md5(coalesce(string_agg(md5(row_to_json(t)::text),"
                f"'' ORDER BY md5(row_to_json(t)::text)),'')) FROM {table} t"
            )
        )
        for table in sorted(Base.metadata.tables)
    }


def test_independent_migration_disable_removal_and_http_pagination(soc):
    factory, settings, config = soc
    dataset, run_id = accept(factory)
    controller = SocController(factory, settings)
    execute(controller, controller.claim())
    app = create_app(settings)
    app.state.session_factory = factory
    auth = {"Authorization": "Bearer " + TOKEN}
    with TestClient(app, base_url="http://localhost:8000") as client:
        path = f"/api/v1/soc/datasets/{dataset}/events?limit=2"
        first = client.get(path, headers=auth).json()
        second = client.get(path + "&cursor=" + first["next_cursor"], headers=auth).json()
        assert len(first["items"]) == len(second["items"]) == 2
        assert not {e["id"] for e in first["items"]} & {e["id"] for e in second["items"]}
        assert (
            client.get(f"/api/v1/soc/runs/{run_id}", headers=auth).json()["status"] == "succeeded"
        )
        found = client.get(f"/api/v1/soc/datasets/{dataset}/investigations", headers=auth).json()
        identifier = found["items"][0]["id"]
        timeline = client.get(f"/api/v1/soc/investigations/{identifier}/timeline", headers=auth)
        assert timeline.status_code == 200
        assert len(timeline.json()["items"]) == 4
        assert {event["id"] for event in timeline.json()["items"]} == {
            event["id"] for event in first["items"] + second["items"]
        }
        assert (
            client.get(
                path.replace(str(dataset), str(uuid4())) + "&cursor=" + first["next_cursor"],
                headers=auth,
            ).status_code
            == 400
        )
        assert (
            client.get("/api/v1/soc/retention", headers=auth).json()["eligible_for_deletion"] == 0
        )
    with factory() as session:
        create_project(session, "Synthetic AppSec preservation record", "soc-removal")
        before = appsec_fingerprints(session)
    command.upgrade(config, "head")

    command.check(config)
    command.downgrade(config, "base")  # Exact disposable identity was asserted by pg_runtime.
    with factory() as session:
        assert appsec_fingerprints(session) == before
    with TestClient(app, base_url="http://localhost:8000") as client:
        assert client.get("/ready").status_code == 200
        assert client.get("/api/v1/soc/retention", headers=auth).status_code == 503
    disabled = create_app(settings.model_copy(update={"soc_enabled": False}))
    disabled.state.session_factory = factory
    with TestClient(disabled, base_url="http://localhost:8000") as client:
        assert client.get("/ready").status_code == 200
        assert client.get("/api/v1/soc/rules", headers=auth).status_code == 404
    command.upgrade(config, "head")


def test_actual_module_removal(soc, tmp_path):
    factory, settings, config = soc
    source = __import__("pathlib").Path("src/ai_security_platform")
    destination = tmp_path / "src" / "ai_security_platform"
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("soc", "__pycache__"))
    assert not (destination / "soc").exists()
    with factory() as session:
        project = create_project(session, "Synthetic AppSec module-removal record", "soc-removal")
        project_id = str(project.id)
        before = appsec_fingerprints(session)
    program = """
import importlib.util,os
from fastapi.testclient import TestClient
from ai_security_platform.api.app import create_app
assert importlib.util.find_spec("ai_security_platform.soc") is None
app=create_app()
with TestClient(app,base_url="http://localhost:8000") as client:
 assert client.get("/ready").status_code == 200
 assert client.get("/health").status_code == 200
 auth={"Authorization":"Bearer "+app.state.settings.api_token.get_secret_value()}
 assert client.get("/api/v1/soc/rules",headers=auth).status_code == 404
 assert client.get("/api/v1/projects/"+os.environ["ASP_SOC_REMOVAL_PROJECT"],
                   headers=auth).status_code == 200
print("module_removed_appsec_ready")
"""
    environment = os.environ | {
        "PYTHONPATH": str(tmp_path / "src"),
        "ASP_DATABASE_URL": settings.database_url.get_secret_value(),
        "ASP_API_TOKEN": TOKEN,
        "ASP_SOC_ENABLED": "false",
        "ASP_SOC_REMOVAL_PROJECT": project_id,
    }
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, "Module-removal subprocess failed; no raw output published"
    assert "module_removed_appsec_ready" in result.stdout
    with factory() as session:
        assert appsec_fingerprints(session) == before
