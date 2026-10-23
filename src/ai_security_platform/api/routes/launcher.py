from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ai_security_platform.api.dependencies import get_session
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.domain.launcher import (
    InvocationIdentity,
    LauncherHello,
    LauncherPoll,
    LauncherResult,
)
from ai_security_platform.jobs.controller import Controller
from ai_security_platform.scanners.contracts import AdapterResult
from ai_security_platform.scanners.real import validate_provenance, validate_result
from ai_security_platform.scanners.registry import load_registry, registry_digest
from ai_security_platform.storage.launcher import current, poll
from ai_security_platform.storage.models import (
    Job,
    LauncherCapability,
    ScannerInvocation,
    ScannerRun,
    ScanRun,
    SourceSnapshot,
)

router = APIRouter(prefix="/internal/v1/launcher", include_in_schema=False)
Database = Annotated[Session, Depends(get_session)]


@router.post("/hello")
def hello(body: LauncherHello, request: Request, session: Database) -> dict[str, bool]:
    try:
        expected = registry_digest(load_registry(request.app.state.settings.scanner_registry))
    except (OSError, ValueError, KeyError):
        raise ApiError(503, "scanner_unavailable", "Scanner capability unavailable") from None
    if body.registry_digest != expected:
        raise ApiError(409, "policy_mismatch", "Scanner policy does not match")
    with session.begin():
        capability = session.get(LauncherCapability, body.launcher_id)
        if capability is None:
            capability = LauncherCapability(id=body.launcher_id)
            session.add(capability)
        capability.registry_digest = body.registry_digest
        capability.gate_digest = body.gate_digest
        capability.seen_at = Controller.now(session)
    return {"accepted": True}


@router.post("/next")
def next_invocation(body: LauncherPoll, session: Database) -> dict[str, Any]:
    return {"invocation": poll(session, body.launcher_id)}


@router.post("/recover")
def recover_launcher(body: LauncherPoll, session: Database) -> dict[str, int]:
    recovered = 0
    # One bounded batch. The host holds an exclusive launcher lock and removes
    # its owned orphan containers BEFORE requesting these retryable failures.
    with session.begin():
        jobs = list(
            session.scalars(
                select(Job)
                .join(ScannerInvocation, ScannerInvocation.job_id == Job.id)
                .where(
                    ScannerInvocation.state == "running",
                    ScannerInvocation.launcher_id != body.launcher_id,
                    Job.state == "running",
                    Job.generation == ScannerInvocation.generation,
                    Job.lease_token == ScannerInvocation.lease_token,
                    Job.lease_expires_at > Controller.now(session),
                    Job.attempt_deadline > Controller.now(session),
                )
                .order_by(Job.id)
                .limit(100)
                .with_for_update(of=Job, skip_locked=True)
            )
        )
        for job in jobs:
            invocation = session.scalars(
                select(ScannerInvocation)
                .where(
                    ScannerInvocation.job_id == job.id,
                    ScannerInvocation.generation == job.generation,
                )
                .with_for_update()
            ).one()
            # Recheck fresh time under ownership before staging any failure.
            now = Controller.now(session)
            if (
                job.lease_expires_at is None
                or job.lease_expires_at <= now
                or job.attempt_deadline is None
                or job.attempt_deadline <= now
            ):
                continue
            invocation.result = {"error_code": "launcher_unavailable"}
            invocation.state = "returned"
            recovered += 1
    return {"recovered": recovered}


@router.post("/{invocation_id}/check")
def check(
    invocation_id: UUID,
    body: InvocationIdentity,
    session: Database,
) -> dict[str, bool]:
    with session.begin():
        _, invocation = current(session, invocation_id, body)
        if invocation.state != "running":
            raise ApiError(409, "lease_lost", "Invocation is not current")
    return {"current": True}


@router.post("/{invocation_id}/result")
def result(
    invocation_id: UUID,
    body: LauncherResult,
    request: Request,
    session: Database,
) -> dict[str, bool]:
    with session.begin():
        snapshot = session.scalars(
            select(SourceSnapshot)
            .join(ScanRun, ScanRun.snapshot_id == SourceSnapshot.id)
            .join(ScannerRun, ScannerRun.scan_run_id == ScanRun.id)
            .join(Job, Job.scanner_run_id == ScannerRun.id)
            .join(ScannerInvocation, ScannerInvocation.job_id == Job.id)
            .where(ScannerInvocation.id == invocation_id)
        ).first()
        if snapshot is None:
            raise ApiError(404, "not_found", "Invocation not found")
        key, manifest_digest = snapshot.spool_key, snapshot.manifest_digest
    # No DB lock/connection while checking source and untrusted result content.
    try:
        if "error_code" in body.result:
            allowed = {
                "database_unavailable",
                "database_stale",
                "output_limit",
                "execution_timeout",
                "launcher_unavailable",
                "invalid_result",
                "execution_failed",
            }
            if set(body.result) != {"error_code"} or body.result["error_code"] not in allowed:
                raise ValueError("invalid_result")
            sanitized = body.result
        else:
            parsed = AdapterResult.model_validate(body.result)
            source = request.app.state.snapshot_store.verify(key, manifest_digest)
            validate_result(parsed, source)
            validate_provenance(parsed, request.app.state.settings.scanner_registry)
            sanitized = parsed.model_dump()
    except (OSError, ValueError, KeyError, TypeError):
        raise ApiError(422, "invalid_result", "Scanner result is invalid") from None
    with session.begin():
        _, invocation = current(session, invocation_id, body)
        if invocation.state != "running":
            raise ApiError(409, "lease_lost", "Invocation is not current")
        invocation.result = sanitized
        invocation.state = "returned"
    return {"accepted": True}
