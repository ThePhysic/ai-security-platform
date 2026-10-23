from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ai_security_platform.config import Settings
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.domain.intake import ScanSubmission, SnapshotRegistration
from ai_security_platform.scanners.contracts import PROFILE_DIGEST, SCANNERS
from ai_security_platform.snapshots.policy import SnapshotError, canonical, digest
from ai_security_platform.snapshots.store import SnapshotStore
from ai_security_platform.storage.models import (
    AuditEvent,
    IdempotencyRequest,
    Job,
    Project,
    ScannerRun,
    ScanRun,
    SourceSnapshot,
)

SCOPE = "local_operator:scan-runs"


def audit(
    session: Session,
    event: str,
    object_type: str,
    object_id: UUID,
    request_id: str,
    *,
    generation: int | None = None,
) -> None:
    worker = event.startswith("job.")
    session.add(
        AuditEvent(
            event_type=event,
            object_type=object_type,
            object_id=object_id,
            actor="worker" if worker else "local_operator",
            component="worker" if worker else "api",
            request_id=request_id,
            event_metadata={} if generation is None else {"generation": generation},
        )
    )


def _registration_replay(session: Session, body: SnapshotRegistration) -> SourceSnapshot | None:
    current = session.scalar(
        select(SourceSnapshot).where(SourceSnapshot.spool_key == body.snapshot_key)
    )
    if current is not None and (
        current.project_id != body.project_id or current.manifest_digest != body.manifest_digest
    ):
        raise ApiError(409, "snapshot_conflict", "Snapshot registration conflicts")
    return current


def register_snapshot(
    session: Session,
    store: SnapshotStore,
    settings: Settings,
    body: SnapshotRegistration,
    request_id: str,
) -> SourceSnapshot:
    with session.begin():
        replay = _registration_replay(session, body)
        if replay is not None:
            return replay
    try:
        verified = store.verify(body.snapshot_key, body.manifest_digest)
    except SnapshotError as exc:
        if str(exc) == "readonly_spool_required":
            raise ApiError(
                503, "snapshot_store_unavailable", "Snapshot store unavailable"
            ) from None
        raise ApiError(409, "snapshot_invalid", "Snapshot identity verification failed") from None
    except OSError:
        raise ApiError(503, "snapshot_store_unavailable", "Snapshot store unavailable") from None
    manifest = verified.manifest
    acquired = datetime.fromtimestamp(manifest.acquired_at, UTC)
    try:
        with session.begin():
            project = session.scalar(
                select(Project).where(Project.id == body.project_id).with_for_update()
            )
            if project is None:
                raise ApiError(404, "not_found", "Project not found")
            now = session.scalar(select(func.clock_timestamp()))
            assert isinstance(now, datetime)
            assert now is not None
            expires = acquired + timedelta(seconds=settings.snapshot_retention_seconds)
            if acquired > now + timedelta(seconds=60) or expires <= now:
                raise ApiError(409, "snapshot_expired", "Snapshot is not eligible for registration")
            snapshot = SourceSnapshot(
                project_id=body.project_id,
                spool_key=body.snapshot_key,
                manifest_version=manifest.version,
                manifest_digest=body.manifest_digest,
                content_digest=manifest.content_digest,
                inclusion_policy_digest=manifest.policy_digest,
                provenance_kind=manifest.provenance_kind,
                provenance_label=manifest.label,
                file_count=len(verified.files),
                byte_count=sum(map(len, verified.files.values())),
                acquired_at=acquired,
                expires_at=expires,
                verified=True,
                retention_state="published",
            )
            session.add(snapshot)
            session.flush()
            audit(session, "snapshot.registered", "source_snapshot", snapshot.id, request_id)
        return snapshot
    except IntegrityError:
        with session.begin():
            replay = _registration_replay(session, body)
            if replay is not None:
                return replay
        raise ApiError(409, "snapshot_conflict", "Snapshot content is already registered") from None


def _scan_replay(session: Session, key: str, payload_hash: str) -> ScanRun | None:
    request = session.scalar(
        select(IdempotencyRequest).where(
            IdempotencyRequest.scope == SCOPE, IdempotencyRequest.key == key
        )
    )
    if request is None:
        return None
    if request.payload_hash != payload_hash:
        raise ApiError(409, "idempotency_conflict", "Idempotency key conflicts")
    scan = session.get(ScanRun, request.scan_run_id)
    assert scan is not None
    return scan


def accept_scan(
    session: Session, settings: Settings, body: ScanSubmission, key: str, request_id: str
) -> ScanRun:
    payload_hash = digest(canonical(body.model_dump(mode="json")))
    try:
        with session.begin():
            replay = _scan_replay(session, key, payload_hash)
            if replay is not None:
                return replay
            project = session.scalar(
                select(Project).where(Project.id == body.project_id).with_for_update()
            )
            if project is None:
                raise ApiError(404, "not_found", "Project not found")
            # A concurrent submit may have committed while this project lock was awaited.
            replay = _scan_replay(session, key, payload_hash)
            if replay is not None:
                return replay
            snapshot = session.get(SourceSnapshot, body.snapshot_id)
            now = session.scalar(select(func.clock_timestamp()))
            assert isinstance(now, datetime)
            if (
                snapshot is None
                or snapshot.project_id != body.project_id
                or not snapshot.verified
                or snapshot.retention_state != "published"
                or snapshot.expires_at is None
                or snapshot.expires_at <= now
            ):
                raise ApiError(409, "snapshot_unavailable", "Snapshot is not eligible")
            pending = session.scalar(
                select(func.count())
                .select_from(Job)
                .join(ScannerRun)
                .join(ScanRun)
                .where(
                    ScanRun.project_id == body.project_id,
                    Job.state.in_(("queued", "running", "retry_pending")),
                )
            )
            if (pending or 0) + len(SCANNERS) > settings.pending_jobs_per_project:
                raise ApiError(429, "capacity_exceeded", "Scan capacity exceeded", retryable=True)
            scan = ScanRun(
                project_id=body.project_id,
                snapshot_id=body.snapshot_id,
                profile_id=body.profile_id,
                profile_digest=PROFILE_DIGEST,
                status="queued",
            )
            session.add(scan)
            session.flush()
            for scanner_id in SCANNERS:
                scanner = ScannerRun(scan_run_id=scan.id, scanner_id=scanner_id, status="queued")
                session.add(scanner)
                session.flush()
                session.add(Job(scanner_run_id=scanner.id, request_id=request_id))
            session.add(
                IdempotencyRequest(
                    scope=SCOPE, key=key, payload_hash=payload_hash, scan_run_id=scan.id
                )
            )
            audit(session, "scan.accepted", "scan", scan.id, request_id)
            session.flush()
        return scan
    except IntegrityError:
        # Constraint is authoritative even when requests lock different projects.
        with session.begin():
            replay = _scan_replay(session, key, payload_hash)
            if replay is not None:
                return replay
        raise
