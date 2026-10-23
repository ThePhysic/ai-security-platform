"""Lease-fenced handoff; host launcher stages sanitized data, worker publishes."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ai_security_platform.domain.errors import ApiError
from ai_security_platform.domain.launcher import InvocationIdentity
from ai_security_platform.storage.models import (
    Job,
    LauncherCapability,
    ScannerInvocation,
    ScannerRun,
    ScanRun,
    SourceSnapshot,
)

if TYPE_CHECKING:
    from ai_security_platform.jobs.controller import Controller, Lease


def dispatch(controller: Controller, lease: Lease) -> UUID:
    from ai_security_platform.jobs.controller import LeaseLost

    with controller.factory.begin() as session:
        job = session.scalars(select(Job).where(Job.id == lease.job_id).with_for_update()).one()
        if not controller.owned(job, lease, controller.now(session)):
            raise LeaseLost("lease_lost")
        invocation = ScannerInvocation(
            job_id=job.id, generation=lease.generation, lease_token=lease.token
        )
        session.add(invocation)
        session.flush()
        return invocation.id


def current(
    session: Session, invocation_id: UUID, identity: InvocationIdentity
) -> tuple[Job, ScannerInvocation]:
    from ai_security_platform.jobs.controller import Controller, Lease

    # Acquire job before handoff row; recovery/publication share the same job fence.
    job = session.scalars(
        select(Job)
        .join(ScannerInvocation, ScannerInvocation.job_id == Job.id)
        .where(ScannerInvocation.id == invocation_id)
        .with_for_update(of=Job)
    ).first()
    if job is None:
        raise ApiError(404, "not_found", "Invocation not found")
    invocation = session.scalars(
        select(ScannerInvocation).where(ScannerInvocation.id == invocation_id).with_for_update()
    ).one()
    lease = Lease(job.id, identity.generation, identity.lease_token, "", "", "")
    if (
        not Controller.owned(job, lease, Controller.now(session))
        or invocation.generation != identity.generation
        or invocation.lease_token != identity.lease_token
        or invocation.launcher_id != identity.launcher_id
    ):
        raise ApiError(409, "lease_lost", "Invocation is not current")
    return job, invocation


def poll(session: Session, launcher_id: UUID) -> dict[str, Any] | None:
    from ai_security_platform.jobs.controller import Controller, Lease

    with session.begin():
        job = session.scalars(
            select(Job)
            .join(ScannerInvocation, ScannerInvocation.job_id == Job.id)
            .where(
                Job.state == "running",
                Job.lease_expires_at > func.clock_timestamp(),
                Job.attempt_deadline > func.clock_timestamp(),
                ScannerInvocation.state == "pending",
                ScannerInvocation.generation == Job.generation,
                ScannerInvocation.lease_token == Job.lease_token,
            )
            .order_by(ScannerInvocation.created_at)
            .limit(1)
            .with_for_update(of=Job, skip_locked=True)
        ).first()
        if job is None:
            return None
        invocation = session.scalars(
            select(ScannerInvocation)
            .where(
                ScannerInvocation.job_id == job.id, ScannerInvocation.generation == job.generation
            )
            .with_for_update()
        ).one()
        if not Controller.owned(
            job,
            Lease(job.id, invocation.generation, invocation.lease_token, "", "", ""),
            Controller.now(session),
        ):
            return None
        invocation.state = "running"
        invocation.launcher_id = launcher_id
        scanner = session.get(ScannerRun, job.scanner_run_id)
        assert scanner is not None
        parent = session.get(ScanRun, scanner.scan_run_id)
        assert parent is not None
        snapshot = session.get(SourceSnapshot, parent.snapshot_id)
        assert snapshot is not None
        return {
            "id": str(invocation.id),
            "job_id": str(job.id),
            "generation": job.generation,
            "lease_token": str(job.lease_token),
            "snapshot_key": snapshot.spool_key,
            "manifest_digest": snapshot.manifest_digest,
            "profile": scanner.scanner_id + "-v1",
            "registry_digest": parent.profile_digest,
        }


def capability_available(session: Session, registry_digest: str) -> bool:
    from ai_security_platform.jobs.controller import Controller

    now = Controller.now(session)
    return (
        session.scalar(
            select(LauncherCapability.id)
            .where(
                LauncherCapability.registry_digest == registry_digest,
                LauncherCapability.seen_at > now - timedelta(seconds=15),
            )
            .limit(1)
        )
        is not None
    )
