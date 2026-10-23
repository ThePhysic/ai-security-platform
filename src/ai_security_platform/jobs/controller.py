"""Short transactions; lock order is always job, scanner, parent scan.

Execution is at least once. Every authoritative worker mutation is guarded by
ownership under the job lock in its publication transaction. Recovery has its
own authority: a locked, expired job, never an expired worker token.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from ai_security_platform.config import Settings
from ai_security_platform.jobs.ownership import clear_lease, owned
from ai_security_platform.scanners.contracts import AdapterResult
from ai_security_platform.scanners.real import validate_provenance, validate_result
from ai_security_platform.snapshots.store import VerifiedSnapshot
from ai_security_platform.storage.intake import audit
from ai_security_platform.storage.models import (
    Finding,
    Job,
    JobAttempt,
    ScannerRun,
    ScanRun,
    SourceSnapshot,
)


class LeaseLost(RuntimeError):
    pass


@dataclass(frozen=True)
class Lease:
    job_id: UUID
    generation: int
    token: UUID
    scanner_id: str
    snapshot_key: str
    manifest_digest: str
    operation: str = "scan"
    triage_run_id: UUID | None = None


class Controller:
    def __init__(self, factory: sessionmaker[Session], settings: Settings):
        self.factory = factory
        self.settings = settings
        self.worker_id = uuid4()

    @staticmethod
    def now(session: Session) -> datetime:
        return session.scalar(select(func.clock_timestamp()))  # type: ignore[return-value]

    @staticmethod
    def lock_dependents(session: Session, job: Job) -> tuple[ScannerRun, ScanRun]:
        scanner = session.scalars(
            select(ScannerRun).where(ScannerRun.id == job.scanner_run_id).with_for_update()
        ).one()
        parent = session.scalars(
            select(ScanRun).where(ScanRun.id == scanner.scan_run_id).with_for_update()
        ).one()
        return scanner, parent

    @staticmethod
    def owned(job: Job, lease: Lease, now: datetime) -> bool:
        return owned(job, lease, now)

    def claim(self) -> Lease | None:
        with self.factory.begin() as session:
            job = session.scalars(
                select(Job)
                .where(
                    Job.operation == "scan",
                    Job.state.in_(["queued", "retry_pending"]),
                    Job.next_attempt_at <= func.clock_timestamp(),
                    Job.attempts < Job.max_attempts,
                )
                .order_by(Job.next_attempt_at, Job.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            ).first()
            if job is None:
                return None
            scanner, parent = self.lock_dependents(session, job)
            now = self.now(session)
            snapshot = session.get(SourceSnapshot, parent.snapshot_id)
            assert snapshot is not None
            job.state = "running"
            job.generation += 1
            job.attempts += 1
            job.worker_id = self.worker_id
            job.lease_token = uuid4()
            job.heartbeat_at = now
            duration = (
                self.settings.attempt_seconds
                if scanner.synthetic
                else self.settings.real_attempt_seconds
            )
            job.attempt_deadline = now + timedelta(seconds=duration)
            job.lease_expires_at = min(
                now + timedelta(seconds=self.settings.lease_seconds), job.attempt_deadline
            )
            job.error_code = None
            scanner.status = "running"
            scanner.started_at = scanner.started_at or now
            parent.status = "running"
            parent.started_at = parent.started_at or now
            session.add(
                JobAttempt(
                    job_id=job.id,
                    generation=job.generation,
                    worker_id=self.worker_id,
                    started_at=now,
                )
            )
            audit(session, "job.claimed", "job", job.id, job.request_id, generation=job.generation)
            return Lease(
                job.id,
                job.generation,
                job.lease_token,
                scanner.scanner_id,
                snapshot.spool_key,
                snapshot.manifest_digest,
            )

    def heartbeat(self, lease: Lease) -> bool:
        with self.factory.begin() as session:
            job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
            now = self.now(session)  # sampled AFTER the lock, never transaction-start time
            if not self.owned(job, lease, now):
                return False
            assert job.attempt_deadline is not None
            job.heartbeat_at = now
            job.lease_expires_at = min(
                now + timedelta(seconds=self.settings.lease_seconds), job.attempt_deadline
            )
            return True

    @staticmethod
    def clear_lease(job: Job) -> None:
        clear_lease(job)

    @staticmethod
    def aggregate(session: Session, scanner: ScannerRun, parent: ScanRun, now: datetime) -> None:
        session.flush()
        states = list(
            session.scalars(select(ScannerRun.status).where(ScannerRun.scan_run_id == parent.id))
        )
        if all(state in {"succeeded", "failed"} for state in states):
            successes = states.count("succeeded")
            parent.status = (
                "succeeded" if successes == len(states) else "partial" if successes else "failed"
            )
            parent.completed_at = now

    def finish(
        self,
        lease: Lease,
        result: AdapterResult,
        source: VerifiedSnapshot,
        checkpoint: Callable[[str], None] = lambda _: None,
    ) -> None:
        # Re-validate even an in-process adapter. All untrusted result checks precede locking.
        result = AdapterResult.model_validate(result.model_dump())
        validate_result(result, source)
        validate_provenance(result, self.settings.scanner_registry)
        if (
            result.scanner_id != lease.scanner_id
            or source.manifest.snapshot_key != lease.snapshot_key
            or source.manifest_digest != lease.manifest_digest
            or result.files_scanned > len(source.files)
            or (lease.scanner_id.startswith("fake-") and result.files_scanned != len(source.files))
        ):
            raise ValueError("invalid_result")
        for finding in result.findings:
            content = source.files.get(finding.filepath)
            if content is None or not (
                finding.start_line <= finding.end_line <= len(content.splitlines())
            ):
                raise ValueError("invalid_result")
        with self.factory.begin() as session:
            job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
            scanner, parent = self.lock_dependents(session, job)
            now = self.now(session)
            if not self.owned(job, lease, now):
                raise LeaseLost("lease_lost")
            for finding in result.findings:
                session.add(
                    Finding(
                        scan_run_id=parent.id,
                        scanner_run_id=scanner.id,
                        job_id=job.id,
                        attempt_generation=lease.generation,
                        **finding.model_dump(),
                    )
                )
            session.flush()
            checkpoint("after_findings")  # trusted tests only; never source-controlled
            # A transaction may have waited or taken too long after its initial fence.
            if not self.owned(job, lease, self.now(session)):
                raise LeaseLost("lease_lost")
            job.state = "succeeded"
            self.clear_lease(job)
            scanner.status = "succeeded" if result.complete else "failed"
            scanner.error_code = None if result.complete else "incomplete_coverage"
            scanner.provenance = result.provenance
            scanner.completed_at = now
            scanner.winning_generation = lease.generation
            scanner.coverage = {
                "schema_version": 1,
                "synthetic": scanner.synthetic,
                "files_scanned": result.files_scanned,
                "excluded_files": result.excluded_files,
                "excluded_directories": result.excluded_directories,
                "complete_detection_claim": False,
                "complete_execution": result.complete,
                "warning_count": len(result.warnings),
                "warnings": result.warnings,
                "source_files": len(source.files),
                "files_not_scanned": len(source.files) - result.files_scanned,
                "policy_files_ignored": result.policy_files_ignored,
                "suppression_tokens_neutralized": result.suppression_tokens_neutralized,
            }
            attempt = session.scalars(
                select(JobAttempt).where(
                    JobAttempt.job_id == job.id, JobAttempt.generation == lease.generation
                )
            ).one()
            attempt.outcome = "succeeded"
            attempt.completed_at = now
            self.aggregate(session, scanner, parent, now)
            audit(
                session, "job.succeeded", "job", job.id, job.request_id, generation=job.generation
            )
        checkpoint("after_commit")

    def _failure(
        self,
        session: Session,
        job: Job,
        scanner: ScannerRun,
        parent: ScanRun,
        now: datetime,
        code: str,
        expired: bool,
        permanent: bool,
    ) -> None:
        attempt = session.scalars(
            select(JobAttempt).where(
                JobAttempt.job_id == job.id, JobAttempt.generation == job.generation
            )
        ).one()
        terminal = permanent or job.attempts >= job.max_attempts
        attempt.outcome = "expired" if expired else "failed" if terminal else "retry_pending"
        attempt.completed_at = now
        attempt.error_code = code
        job.error_code = code
        job.state = "terminal_failed" if terminal else "retry_pending"
        self.clear_lease(job)
        # Bounded deterministic jitter from a platform UUID, never repository material.
        jitter = (job.id.int % 100) / 100
        delay = min(60, self.settings.retry_base_seconds * 2 ** (job.attempts - 1))
        job.next_attempt_at = now + timedelta(seconds=delay * (1 + jitter / 4))
        if terminal:
            scanner.status = "failed"
            scanner.completed_at = now
            scanner.error_code = code
            scanner.coverage = {"schema_version": 1, "synthetic": True, "unavailable": True}
            self.aggregate(session, scanner, parent, now)
        event = "job.expired" if expired else "job.failed" if terminal else "job.retry_pending"
        audit(session, event, "job", job.id, job.request_id, generation=job.generation)

    def fail(self, lease: Lease, code: str, *, permanent: bool = False) -> None:
        if code not in {
            "snapshot_unavailable",
            "invalid_result",
            "execution_failed",
            "database_unavailable",
            "database_stale",
            "output_limit",
            "execution_timeout",
            "launcher_unavailable",
        }:
            raise ValueError("invalid_error_code")
        with self.factory.begin() as session:
            job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
            scanner, parent = self.lock_dependents(session, job)
            now = self.now(session)
            if not self.owned(job, lease, now):
                raise LeaseLost("lease_lost")
            self._failure(session, job, scanner, parent, now, code, False, permanent)

    def recover_one(self) -> bool:
        with self.factory.begin() as session:
            job = session.scalars(
                select(Job)
                .where(
                    Job.operation == "scan",
                    Job.state == "running",
                    Job.lease_expires_at <= func.clock_timestamp(),
                )
                .order_by(Job.lease_expires_at, Job.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            ).first()
            if job is None:
                return False
            scanner, parent = self.lock_dependents(session, job)
            now = self.now(session)
            # Heartbeat/completion/reclaimer serialize on the same job lock.
            if job.lease_expires_at is None or job.lease_expires_at > now:
                return False
            self._failure(session, job, scanner, parent, now, "lease_expired", True, False)
            return True
