"""Atomic acceptance/consent/review. No provider or evidence calls in transactions."""

from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ai_security_platform.agent.contracts import ConsentCreate, ReviewWrite, TriageSubmission
from ai_security_platform.agent.policy import (
    CATEGORIES,
    POLICY_VERSION,
    PROMPT_VERSION,
    TOOLS_VERSION,
    configuration,
    plain,
)
from ai_security_platform.config import Settings
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.jobs.controller import Controller
from ai_security_platform.snapshots.policy import canonical, digest
from ai_security_platform.storage.intake import audit
from ai_security_platform.storage.models import (
    Finding,
    HostedConsent,
    IdempotencyRequest,
    Job,
    Review,
    ReviewRevision,
    ScanRun,
    SourceSnapshot,
    TriageOutcome,
    TriageRun,
)


def finding_scope(session: Session, finding_id: UUID) -> tuple[Finding, ScanRun, SourceSnapshot]:
    row = session.execute(
        select(Finding, ScanRun, SourceSnapshot)
        .join(ScanRun, Finding.scan_run_id == ScanRun.id)
        .join(SourceSnapshot, ScanRun.snapshot_id == SourceSnapshot.id)
        .where(Finding.id == finding_id)
    ).first()
    if row is None:
        raise ApiError(404, "not_found", "Finding not found")
    return row[0], row[1], row[2]


def valid_consent(
    consent: HostedConsent | None,
    operation: UUID,
    finding: UUID,
    scan: UUID,
    snapshot: UUID,
    manifest: str,
    config: str,
) -> bool:
    return bool(
        consent is not None
        and consent.revoked_at is None
        and consent.operation_id == operation
        and consent.finding_id == finding
        and consent.scan_run_id == scan
        and consent.snapshot_id == snapshot
        and consent.manifest_digest == manifest
        and consent.config_digest == config
        and set(consent.data_categories) == set(CATEGORIES)
    )


def create_consent(
    session: Session, settings: Settings, body: ConsentCreate, request_id: str
) -> HostedConsent:
    if (
        not settings.hosted_enabled
        or body.config_digest != configuration("openai-v1")["config_digest"]
        or set(body.data_categories) != set(CATEGORIES)
    ):
        raise ApiError(403, "consent_denied", "Hosted consent scope is not enabled or complete")
    try:
        with session.begin():
            _, scan, snapshot = finding_scope(session, body.finding_id)
            row = HostedConsent(
                operation_id=body.operation_id,
                finding_id=body.finding_id,
                scan_run_id=scan.id,
                snapshot_id=snapshot.id,
                manifest_digest=snapshot.manifest_digest,
                config_digest=body.config_digest,
                data_categories=sorted(set(body.data_categories)),
            )
            session.add(row)
            session.flush()
            audit(session, "consent.created", "consent", row.id, request_id)
        return row
    except IntegrityError:
        raise ApiError(409, "consent_conflict", "Operation already has consent") from None


def accept_triage(
    session: Session,
    settings: Settings,
    finding_id: UUID,
    body: TriageSubmission,
    key: str,
    request_id: str,
) -> TriageRun:
    scope = "local_operator:triage:" + str(finding_id)
    payload_hash = digest(canonical(body.model_dump(mode="json") | {"finding_id": str(finding_id)}))

    def replay() -> TriageRun | None:
        record = session.scalar(
            select(IdempotencyRequest).where(
                IdempotencyRequest.scope == scope, IdempotencyRequest.key == key
            )
        )
        if record is None:
            return None
        if record.payload_hash != payload_hash:
            raise ApiError(409, "idempotency_conflict", "Idempotency payload conflicts")
        assert record.triage_run_id is not None
        return session.get(TriageRun, record.triage_run_id)

    with session.begin():
        original = replay()
        if original is not None:
            return original
    if not settings.triage_enabled:
        raise ApiError(503, "triage_unavailable", "Triage is disabled")
    if body.provider == "deterministic-v1" and body.consent_id is not None:
        raise ApiError(422, "invalid_consent", "Offline triage does not use hosted consent")
    if body.provider == "openai-v1" and (
        not settings.hosted_enabled or body.operation_id is None or body.consent_id is None
    ):
        raise ApiError(403, "consent_required", "Hosted triage requires enabled scoped consent")
    try:
        with session.begin():
            finding, scan, snapshot = finding_scope(session, finding_id)
            # Serialize capacity/acceptance for this project without changing scanner states.
            from ai_security_platform.storage.models import Project

            session.scalar(select(Project).where(Project.id == scan.project_id).with_for_update())
            original = replay()
            if original is not None:
                return original
            count = session.scalar(
                select(func.count())
                .select_from(TriageRun)
                .join(ScanRun, TriageRun.scan_run_id == ScanRun.id)
                .where(
                    ScanRun.project_id == scan.project_id,
                    TriageRun.status.in_(["queued", "running"]),
                )
            )
            if count is not None and count >= settings.pending_jobs_per_project:
                raise ApiError(429, "capacity_exceeded", "Triage capacity exceeded")
            config = str(configuration(body.provider)["config_digest"])
            operation = body.operation_id or uuid4()
            if body.provider == "openai-v1":
                consent = session.scalar(
                    select(HostedConsent)
                    .where(HostedConsent.id == body.consent_id)
                    .with_for_update()
                )
                if not valid_consent(
                    consent,
                    operation,
                    finding_id,
                    scan.id,
                    snapshot.id,
                    snapshot.manifest_digest,
                    config,
                ):
                    raise ApiError(
                        403, "consent_denied", "Hosted consent does not authorize this operation"
                    )
            row = TriageRun(
                id=operation,
                finding_id=finding.id,
                scan_run_id=scan.id,
                snapshot_id=snapshot.id,
                manifest_digest=snapshot.manifest_digest,
                provider=body.provider,
                config_digest=config,
                prompt_version=PROMPT_VERSION,
                tools_version=TOOLS_VERSION,
                policy_version=POLICY_VERSION,
                consent_id=body.consent_id,
            )
            session.add(row)
            session.flush()
            session.add(Job(operation="triage", triage_run_id=row.id, request_id=request_id))
            session.add(
                IdempotencyRequest(
                    scope=scope, key=key, payload_hash=payload_hash, triage_run_id=row.id
                )
            )
            audit(session, "triage.accepted", "triage", row.id, request_id)
        return row
    except IntegrityError:
        with session.begin():
            original = replay()
            if original is not None:
                return original
        raise ApiError(409, "operation_conflict", "Triage operation identity conflicts") from None


def read_triage(session: Session, identifier: UUID) -> dict[str, Any]:
    row = session.get(TriageRun, identifier)
    if row is None:
        raise ApiError(404, "not_found", "Triage not found")
    outcome = session.get(TriageOutcome, identifier)
    return {
        "id": row.id,
        "finding_id": row.finding_id,
        "scan_run_id": row.scan_run_id,
        "snapshot_id": row.snapshot_id,
        "manifest_digest": row.manifest_digest,
        "provider": row.provider,
        "config_digest": row.config_digest,
        "prompt_version": row.prompt_version,
        "tools_version": row.tools_version,
        "policy_version": row.policy_version,
        "status": row.status,
        "error_code": row.error_code,
        "created_at": row.created_at,
        "completed_at": row.completed_at,
        "assessment": outcome.result if outcome else None,
        "trace": outcome.trace if outcome else [],
        "usage": outcome.usage if outcome else {},
        "human_decision": False,
    }


def review_read(row: Review | ReviewRevision) -> dict[str, Any]:
    return {
        "finding_id": row.finding_id,
        "revision": row.revision,
        "disposition": row.disposition,
        "note": row.note,
        "reviewer": "local_operator",
    }


def write_review(
    session: Session,
    finding_id: UUID,
    body: ReviewWrite,
    request_id: str,
    checkpoint: Callable[[], None] = lambda: None,
) -> dict[str, Any]:
    note = plain(body.note)
    if len(note) > 2000 or ((body.feedback is None) != (body.triage_run_id is None)):
        raise ApiError(422, "invalid_review", "Review explanation or feedback is invalid")
    with session.begin():
        # Finding lock also serializes first writes, when no current review row exists.
        finding = session.scalar(select(Finding).where(Finding.id == finding_id).with_for_update())
        if finding is None:
            raise ApiError(404, "not_found", "Finding not found")
        current = session.get(Review, finding_id)
        if body.expected_revision != (current.revision if current else 0):
            raise ApiError(409, "review_conflict", "Review revision has changed")
        if body.triage_run_id is not None:
            triage = session.get(TriageRun, body.triage_run_id)
            if triage is None or triage.finding_id != finding_id or triage.status != "succeeded":
                raise ApiError(
                    409,
                    "feedback_conflict",
                    "Feedback requires this finding's completed assessment",
                )
        revision = body.expected_revision + 1
        if current is None:
            current = Review(finding_id=finding_id)
            session.add(current)
        current.revision, current.disposition, current.note = revision, body.disposition, note
        current.updated_at = Controller.now(session)
        session.add(
            ReviewRevision(
                finding_id=finding_id,
                revision=revision,
                disposition=body.disposition,
                note=note,
                triage_run_id=body.triage_run_id,
                feedback=body.feedback,
            )
        )
        session.flush()
        checkpoint()  # maintained transaction-failure tests only
        audit(session, "review.updated", "review", finding_id, request_id)
    return review_read(current)
