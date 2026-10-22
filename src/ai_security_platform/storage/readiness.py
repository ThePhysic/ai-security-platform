"""Bound wall-clock readiness even when OS/Docker DNS ignores connect_timeout."""

from concurrent.futures import Future, TimeoutError
from threading import Lock, Thread

from sqlalchemy import Engine, text

from ai_security_platform.storage.base import EXPECTED_REVISION


class DatabaseReadiness:
    """One in-flight probe per app; no queue or business-job execution."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._pending: Future[str] | None = None

    def check(self, engine: Engine, timeout: float) -> str:
        with self._lock:
            if self._pending is None or self._pending.done():
                future: Future[str] = Future()
                self._pending = future
                Thread(target=self._probe, args=(engine, future), daemon=True).start()
            pending = self._pending
        try:
            return pending.result(timeout=timeout)
        except TimeoutError:
            return "dependency_unavailable"

    @staticmethod
    def _probe(engine: Engine, future: Future[str]) -> None:
        try:
            with engine.connect() as connection:
                revisions = connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalars()
                status = "ready" if list(revisions) == [EXPECTED_REVISION] else "schema_unavailable"
        except Exception:
            status = "dependency_unavailable"
        future.set_result(status)
