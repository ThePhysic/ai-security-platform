"""Independent triage targets using the existing jobs, attempts and lease machinery."""

from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ai_security_platform.agent.engine import Investigation, validate_assessment
from ai_security_platform.agent.policy import LIMITS, AgentError, configuration
from ai_security_platform.agent.tools import EvidenceTools
from ai_security_platform.jobs.controller import Controller, Lease, LeaseLost
from ai_security_platform.storage.intake import audit
from ai_security_platform.storage.models import (
    HostedConsent,
    Job,
    JobAttempt,
    ProviderCall,
    SourceSnapshot,
    TriageOutcome,
    TriageRun,
)
from ai_security_platform.storage.triage import valid_consent

FAILURES = {
    "provider_timeout",
    "provider_rate_limited",
    "provider_unavailable",
    "invalid_provider_output",
    "invalid_citation",
    "insufficient_evidence",
    "tool_denied",
    "tool_budget",
    "context_budget",
    "token_budget",
    "time_budget",
    "cost_budget",
    "confidentiality_denied",
    "evidence_unavailable",
    "consent_denied",
    "configuration_changed",
    "lease_expired",
}


class TriageController(Controller):
    @staticmethod
    def target(session: Session, job: Job) -> TriageRun:
        return session.scalars(
            select(TriageRun).where(TriageRun.id == job.triage_run_id).with_for_update()
        ).one()

    def claim(self) -> Lease | None:
        with self.factory.begin() as session:
            job = session.scalars(
                select(Job)
                .where(
                    Job.operation == "triage",
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
            triage = self.target(session, job)
            snapshot = session.get(SourceSnapshot, triage.snapshot_id)
            assert snapshot is not None
            now = self.now(session)
            job.state, job.generation, job.attempts = (
                "running",
                job.generation + 1,
                job.attempts + 1,
            )
            job.worker_id, job.lease_token, job.heartbeat_at = self.worker_id, uuid4(), now
            job.attempt_deadline = now + timedelta(seconds=self.settings.attempt_seconds)
            job.lease_expires_at = min(
                now + timedelta(seconds=self.settings.lease_seconds), job.attempt_deadline
            )
            job.error_code = None
            triage.status, triage.started_at = "running", triage.started_at or now
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
                "",
                snapshot.spool_key,
                snapshot.manifest_digest,
                operation="triage",
                triage_run_id=triage.id,
            )

    def authorize(self, lease: Lease, sequence: int, cost: int, tokens: int = 0) -> None:
        if (
            not 1 <= sequence <= LIMITS.provider_calls
            or not 0 <= cost <= 50000
            or not 0 < tokens <= LIMITS.token_upper_bound
        ):
            raise AgentError("cost_budget")
        with self.factory.begin() as session:
            job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
            triage = self.target(session, job)
            if not self.owned(job, lease, self.now(session)):
                raise LeaseLost("lease_lost")
            if (
                triage.id != lease.triage_run_id
                or triage.config_digest != configuration(triage.provider)["config_digest"]
            ):
                raise AgentError("configuration_changed")
            if triage.provider != "openai-v1":
                return
            if not self.settings.hosted_enabled:
                raise AgentError("consent_denied")
            consent = session.scalar(
                select(HostedConsent).where(HostedConsent.id == triage.consent_id).with_for_update()
            )
            if not valid_consent(
                consent,
                triage.id,
                triage.finding_id,
                triage.scan_run_id,
                triage.snapshot_id,
                triage.manifest_digest,
                triage.config_digest,
            ):
                raise AgentError("consent_denied")
            totals = session.execute(
                select(
                    func.count(),
                    func.coalesce(func.sum(ProviderCall.reserved_micro_usd), 0),
                    func.coalesce(func.sum(ProviderCall.reserved_tokens), 0),
                ).where(ProviderCall.triage_run_id == triage.id)
            ).one()
            if (
                totals[0] >= LIMITS.provider_calls
                or totals[1] + cost > LIMITS.cost_micro_usd
                or totals[2] + tokens > LIMITS.token_upper_bound
            ):
                raise AgentError("cost_budget")
            session.add(
                ProviderCall(
                    triage_run_id=triage.id,
                    job_id=job.id,
                    generation=job.generation,
                    sequence=sequence,
                    consent_id=triage.consent_id,
                    reserved_micro_usd=cost,
                    reserved_tokens=tokens,
                )
            )
            audit(
                session,
                "triage.send_reserved",
                "triage",
                triage.id,
                job.request_id,
                generation=job.generation,
            )
            if not self.owned(job, lease, self.now(session)):
                raise LeaseLost("lease_lost")

    def finish_triage(
        self,
        lease: Lease,
        result: Investigation,
        tools: EvidenceTools | None,
        checkpoint: Callable[[str], None] = lambda _: None,
    ) -> None:
        if tools is not None:
            assessment = validate_assessment(result.assessment, tools)
        elif (
            result.assessment.assessment == "abstain"
            and not result.assessment.citations
            and result.assessment.reason == "source_unavailable"
        ):
            assessment = result.assessment
        else:
            raise AgentError("invalid_citation")
        with self.factory.begin() as session:
            job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
            triage = self.target(session, job)
            if not self.owned(job, lease, self.now(session)) or lease.triage_run_id != triage.id:
                raise LeaseLost("lease_lost")
            if tools is not None and (
                tools.finding_id != triage.finding_id
                or tools.snapshot_id != triage.snapshot_id
                or tools.manifest_digest != triage.manifest_digest
            ):
                raise AgentError("invalid_citation")
            session.add(
                TriageOutcome(
                    triage_run_id=triage.id,
                    job_id=job.id,
                    generation=lease.generation,
                    result=assessment.model_dump(mode="json"),
                    trace=result.trace,
                    usage=result.usage,
                )
            )
            session.flush()
            checkpoint("after_outcome")
            if not self.owned(job, lease, self.now(session)):
                raise LeaseLost("lease_lost")
            now = self.now(session)
            job.state, triage.status, triage.completed_at = "succeeded", "succeeded", now
            triage.error_code = None
            self.clear_lease(job)
            attempt = session.scalars(
                select(JobAttempt).where(
                    JobAttempt.job_id == job.id, JobAttempt.generation == job.generation
                )
            ).one()
            attempt.outcome, attempt.completed_at = "succeeded", now
            audit(
                session, "job.succeeded", "job", job.id, job.request_id, generation=job.generation
            )
        checkpoint("after_commit")

    def failure(
        self,
        session: Session,
        job: Job,
        triage: TriageRun,
        now: datetime,
        code: str,
        *,
        expired: bool,
        permanent: bool,
    ) -> None:
        attempt = session.scalars(
            select(JobAttempt).where(
                JobAttempt.job_id == job.id, JobAttempt.generation == job.generation
            )
        ).one()
        terminal = permanent or job.attempts >= job.max_attempts
        attempt.outcome, attempt.completed_at, attempt.error_code = (
            "expired" if expired else "failed" if terminal else "retry_pending",
            now,
            code,
        )
        job.state, job.error_code = "terminal_failed" if terminal else "retry_pending", code
        self.clear_lease(job)
        delay = min(60, self.settings.retry_base_seconds * 2 ** (job.attempts - 1))
        job.next_attempt_at = now + timedelta(seconds=delay * (1 + (job.id.int % 100) / 400))
        if terminal:
            triage.status = (
                "unavailable"
                if code
                in {
                    "provider_timeout",
                    "provider_unavailable",
                    "provider_rate_limited",
                    "evidence_unavailable",
                }
                else "failed"
            )
            triage.error_code, triage.completed_at = code, now
        audit(
            session,
            "job.expired" if expired else "job.failed" if terminal else "job.retry_pending",
            "job",
            job.id,
            job.request_id,
            generation=job.generation,
        )

    def fail(self, lease: Lease, code: str, *, permanent: bool = False) -> None:
        if code not in FAILURES:
            raise ValueError("invalid_error_code")
        with self.factory.begin() as session:
            job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
            triage = self.target(session, job)
            if not self.owned(job, lease, self.now(session)):
                raise LeaseLost("lease_lost")
            self.failure(
                session, job, triage, self.now(session), code, expired=False, permanent=permanent
            )

    def recover_one(self) -> bool:
        with self.factory.begin() as session:
            job = session.scalars(
                select(Job)
                .where(
                    Job.operation == "triage",
                    Job.state == "running",
                    Job.lease_expires_at <= func.clock_timestamp(),
                )
                .order_by(Job.lease_expires_at, Job.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            ).first()
            if job is None:
                return False
            triage = self.target(session, job)
            now = self.now(session)
            if job.lease_expires_at is None or job.lease_expires_at > now:
                return False
            self.failure(session, job, triage, now, "lease_expired", expired=True, permanent=False)
            return True
