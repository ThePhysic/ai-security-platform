"""Separate durable worker. Only fixed fake adapters are available in Phase 2A."""

import signal
from contextlib import suppress
from threading import Event, Thread

from sqlalchemy.exc import SQLAlchemyError

from ai_security_platform.config import load_settings
from ai_security_platform.jobs.controller import Controller, Lease, LeaseLost
from ai_security_platform.scanners.fake import scan
from ai_security_platform.snapshots.policy import SnapshotError
from ai_security_platform.snapshots.store import SnapshotStore
from ai_security_platform.storage.readiness import DatabaseReadiness
from ai_security_platform.storage.session import build_engine, session_factory


class HeartbeatUncertain(RuntimeError):
    """Do not claim more work if an OS-level connection outlives its timeout."""


def execute(controller: Controller, lease: Lease, store: SnapshotStore) -> None:
    stop = Event()
    lost = Event()

    def heartbeat() -> None:
        while not stop.wait(controller.settings.heartbeat_seconds):
            try:
                if controller.heartbeat(lease):
                    continue
            except SQLAlchemyError:
                pass
            lost.set()
            return

    thread = Thread(target=heartbeat, name="lease-heartbeat", daemon=True)
    thread.start()
    try:
        try:
            source = store.verify(lease.snapshot_key, lease.manifest_digest)
        except (SnapshotError, OSError):
            if not lost.is_set():
                controller.fail(lease, "snapshot_unavailable", permanent=True)
            return
        result = scan(lease.scanner_id, source)
        if not lost.is_set():
            controller.finish(lease, result, source)
    except LeaseLost:
        pass
    except (ValueError, SnapshotError):
        if not lost.is_set():
            with suppress(LeaseLost):
                controller.fail(lease, "invalid_result", permanent=True)
    finally:
        stop.set()
        thread.join(timeout=controller.settings.database_timeout_seconds + 2)
        if thread.is_alive():
            raise HeartbeatUncertain("heartbeat_unavailable")


def main() -> None:
    settings = load_settings()
    engine = build_engine(settings)
    controller = Controller(session_factory(engine), settings)
    store = SnapshotStore(settings.snapshot_spool)
    stop = Event()
    readiness = DatabaseReadiness()
    for name in (signal.SIGTERM, signal.SIGINT):
        signal.signal(name, lambda *_: stop.set())
    try:
        while not stop.is_set():
            try:
                if readiness.check(engine, settings.database_timeout_seconds) != "ready":
                    stop.wait(settings.poll_seconds)
                    continue
                controller.recover_one()
                lease = controller.claim()
                if lease is not None:
                    execute(controller, lease, store)
                    continue
            except SQLAlchemyError:
                # Never format driver errors, SQL parameters, settings or source.
                pass
            except HeartbeatUncertain:
                stop.set()
            stop.wait(settings.poll_seconds)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
