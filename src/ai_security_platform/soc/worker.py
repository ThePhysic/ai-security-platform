"""Separate, capability-free process; no source, scanner, network or model tools."""

import signal
from contextlib import suppress
from threading import Event, Thread

from sqlalchemy.exc import SQLAlchemyError

from ai_security_platform.config import load_settings
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.jobs.controller import LeaseLost
from ai_security_platform.jobs.worker import HeartbeatUncertain
from ai_security_platform.soc.controller import Lease, SocController
from ai_security_platform.storage.session import build_engine, session_factory


def execute(controller: SocController, lease: Lease) -> None:
    stop, lost = Event(), Event()

    def heartbeat() -> None:
        while not stop.wait(controller.settings.heartbeat_seconds):
            try:
                if controller.heartbeat(lease):
                    continue
            except SQLAlchemyError:
                pass
            lost.set()
            return

    thread = Thread(target=heartbeat, daemon=True, name="soc-heartbeat")
    thread.start()
    try:
        result = controller.compute(lease)
        if not lost.is_set():
            controller.finish(lease, result)
    except LeaseLost:
        pass
    except (ValueError, KeyError, TypeError):
        if not lost.is_set():
            with suppress(LeaseLost):
                controller.fail(lease, permanent=True)
    finally:
        stop.set()
        thread.join(timeout=controller.settings.database_timeout_seconds + 2)
        if thread.is_alive():
            raise HeartbeatUncertain("heartbeat_unavailable")


def main() -> None:
    settings = load_settings()
    if not settings.soc_enabled:
        raise SystemExit("SOC is disabled; no work was claimed")
    engine = build_engine(settings)
    controller, stop = SocController(session_factory(engine), settings), Event()
    for name in (signal.SIGINT, signal.SIGTERM):
        signal.signal(name, lambda *_: stop.set())
    try:
        while not stop.is_set():
            try:
                controller.recover_one()
                lease = controller.claim()
                if lease:
                    execute(controller, lease)
                    continue
            except (SQLAlchemyError, ApiError):
                pass  # bounded polling; no database exception/URL logging
            except HeartbeatUncertain:
                stop.set()
            stop.wait(settings.poll_seconds)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
