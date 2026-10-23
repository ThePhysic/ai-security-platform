"""Same PostgreSQL orchestration protocol, with optional-module-owned target tables.

Lock order: SOC job, correlation run, attempt. No AppSec rows are locked or written.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ai_security_platform.config import Settings
from ai_security_platform.jobs.controller import Controller, LeaseLost
from ai_security_platform.jobs.ownership import clear_lease, owned
from ai_security_platform.soc.contracts import RULE_DIGEST, fingerprint
from ai_security_platform.soc.correlation import correlate
from ai_security_platform.soc.models import (
    Attempt,
    CorrelationRun,
    Investigation,
    Job,
    SecurityEvent,
)
from ai_security_platform.soc.store import audit, event_read, ready


@dataclass(frozen=True)
class Lease:
    job_id: UUID
    run_id: UUID
    generation: int
    token: UUID
    operation: str = "soc"


class SocController:
    def __init__(self, factory: sessionmaker[Session], settings: Settings):
        self.factory, self.settings, self.worker_id = factory, settings, uuid4()

    def enabled(self) -> None:
        if not self.settings.soc_enabled:
            raise ValueError("soc_disabled")

    @staticmethod
    def target(session: Session, job: Job) -> CorrelationRun:
        return session.scalars(
            select(CorrelationRun).where(CorrelationRun.id == job.run_id).with_for_update()
        ).one()

    def claim(self) -> Lease | None:
        self.enabled()
        with self.factory.begin() as session:
            ready(session)
            job = session.scalar(
                select(Job)
                .where(
                    Job.state.in_(["queued", "retry_pending"]),
                    Job.next_attempt_at <= func.clock_timestamp(),
                    Job.attempts < Job.max_attempts,
                )
                .order_by(Job.next_attempt_at, Job.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if job is None:
                return None
            run = self.target(session, job)
            now = Controller.now(session)
            job.state, run.status = "running", "running"
            job.generation += 1
            job.attempts += 1
            job.worker_id, job.lease_token, job.heartbeat_at = self.worker_id, uuid4(), now
            job.attempt_deadline = now + timedelta(seconds=self.settings.attempt_seconds)
            job.lease_expires_at = min(
                job.attempt_deadline, now + timedelta(seconds=self.settings.lease_seconds)
            )
            job.error_code = None
            session.add(Attempt(job_id=job.id, generation=job.generation, started_at=now))
            audit(session, "job.claimed", job.id, job.request_id, job.generation)
            return Lease(job.id, run.id, job.generation, job.lease_token)

    def heartbeat(self, lease: Lease) -> bool:
        self.enabled()
        with self.factory.begin() as session:
            job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
            now = Controller.now(session)
            if job.run_id != lease.run_id or not owned(job, lease, now):
                return False
            assert job.attempt_deadline is not None
            job.heartbeat_at = now
            job.lease_expires_at = min(
                job.attempt_deadline, now + timedelta(seconds=self.settings.lease_seconds)
            )
            return True

    @staticmethod
    def inputs(session: Session, run: CorrelationRun) -> list[dict[str, Any]]:
        rows = list(
            session.scalars(
                select(SecurityEvent)
                .where(
                    SecurityEvent.dataset_id == run.dataset_id,
                    SecurityEvent.id.in_([UUID(value) for value in run.event_ids]),
                )
                .limit(1001)
            )
        )
        if len(rows) != len(run.event_ids) or run.rules_digest != RULE_DIGEST:
            raise ValueError("evidence_unavailable")
        result = []
        for row in rows:
            if fingerprint(row.canonical) != row.payload_digest:
                raise ValueError("evidence_unavailable")
            result.append(
                event_read(row) | {"id": str(row.id), "occurred_at": row.occurred_at.isoformat()}
            )
        return result

    def compute(self, lease: Lease) -> list[dict[str, Any]]:
        self.enabled()
        with self.factory() as session:
            run = session.get(CorrelationRun, lease.run_id)
            if run is None:
                raise ValueError("evidence_unavailable")
            return correlate(self.inputs(session, run))

    def finish(
        self,
        lease: Lease,
        result: list[dict[str, Any]],
        checkpoint: Callable[[str], None] = lambda _: None,
    ) -> None:
        self.enabled()
        with self.factory.begin() as session:
            job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
            run = self.target(session, job)
            if run.id != lease.run_id or not owned(job, lease, Controller.now(session)):
                raise LeaseLost("lease_lost")
            # Recompute against server-owned events; caller cannot invent evidence or outcomes.
            if result != correlate(self.inputs(session, run)):
                raise ValueError("invalid_result")
            for item in result:
                session.add(
                    Investigation(
                        dataset_id=run.dataset_id,
                        run_id=run.id,
                        job_id=job.id,
                        generation=lease.generation,
                        **item,
                    )
                )
            session.flush()
            checkpoint("after_investigations")
            now = Controller.now(session)
            if not owned(job, lease, now):
                raise LeaseLost("lease_lost")
            run.status, run.completed_at, job.state = "succeeded", now, "succeeded"
            clear_lease(job)
            attempt = session.scalars(
                select(Attempt).where(
                    Attempt.job_id == job.id, Attempt.generation == job.generation
                )
            ).one()
            attempt.outcome, attempt.completed_at = "succeeded", now
            audit(session, "job.succeeded", job.id, job.request_id, job.generation)
        checkpoint("after_commit")

    def failure(
        self,
        session: Session,
        job: Job,
        run: CorrelationRun,
        now: datetime,
        *,
        expired: bool,
        permanent: bool,
    ) -> None:
        terminal = permanent or job.attempts >= job.max_attempts
        job.state = "terminal_failed" if terminal else "retry_pending"
        job.error_code = "lease_expired" if expired else "correlation_failed"
        clear_lease(job)
        delay = min(60, self.settings.retry_base_seconds * 2 ** (job.attempts - 1))
        job.next_attempt_at = now + timedelta(seconds=delay * (1 + (job.id.int % 100) / 400))
        attempt = session.scalars(
            select(Attempt).where(Attempt.job_id == job.id, Attempt.generation == job.generation)
        ).one()
        attempt.outcome = "expired" if expired else "failed" if terminal else "retry_pending"
        attempt.completed_at = now
        if terminal:
            run.status, run.completed_at = "failed", now
        audit(
            session,
            "job.expired" if expired else "job.failed" if terminal else "job.retry_pending",
            job.id,
            job.request_id,
            job.generation,
        )

    def fail(self, lease: Lease, *, permanent: bool = False) -> None:
        self.enabled()
        with self.factory.begin() as session:
            job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
            run = self.target(session, job)
            now = Controller.now(session)
            if run.id != lease.run_id or not owned(job, lease, now):
                raise LeaseLost("lease_lost")
            self.failure(session, job, run, now, expired=False, permanent=permanent)

    def recover_one(self) -> bool:
        self.enabled()
        with self.factory.begin() as session:
            ready(session)
            job = session.scalar(
                select(Job)
                .where(Job.state == "running", Job.lease_expires_at <= func.clock_timestamp())
                .order_by(Job.lease_expires_at, Job.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if job is None:
                return False
            run = self.target(session, job)
            now = Controller.now(session)
            if job.lease_expires_at is None or job.lease_expires_at > now:
                return False
            self.failure(session, job, run, now, expired=True, permanent=False)
            return True
