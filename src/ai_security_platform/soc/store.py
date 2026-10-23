"""Bounded synchronous transactions and database-enforced replay identity."""

from datetime import timedelta
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ai_security_platform.domain.errors import ApiError
from ai_security_platform.jobs.controller import Controller
from ai_security_platform.soc.contracts import (
    RULE_DIGEST,
    RULES,
    DatasetCreate,
    Ingest,
    ReviewWrite,
    fingerprint,
)
from ai_security_platform.soc.models import (
    AnalystFeedback,
    Audit,
    CorrelationRun,
    Dataset,
    Investigation,
    Job,
    SecurityEvent,
)

REVISION = "soc_0001"


def ready(session: Session) -> None:
    # Optional schema mismatch affects SOC only, never flagship readiness.
    exists = session.scalar(text("SELECT to_regclass('soc.alembic_version') IS NOT NULL"))
    if not exists:
        raise ApiError(503, "soc_schema_unavailable", "SOC migration is required")
    if list(session.scalars(text("SELECT version_num FROM soc.alembic_version"))) != [REVISION]:
        raise ApiError(503, "soc_schema_unavailable", "SOC schema is unavailable")


def audit(
    session: Session, event: str, object_id: UUID, request_id: str, generation: int | None = None
) -> None:
    session.add(
        Audit(event=event, object_id=object_id, request_id=request_id, generation=generation)
    )


def create_dataset(session: Session, body: DatasetCreate, request_id: str) -> dict[str, Any]:
    with session.begin():
        ready(session)
        # One fixed advisory lock bounds creation globally; never acquired after a dataset lock.
        session.execute(text("SELECT pg_advisory_xact_lock(735008)"))
        row = session.get(Dataset, body.id)
        if row is None:
            if (session.scalar(select(func.count()).select_from(Dataset)) or 0) >= 32:
                raise ApiError(429, "soc_capacity", "Synthetic dataset quota reached")
            row = Dataset(id=body.id, label=body.label)
            session.add(row)
            audit(session, "dataset.created", row.id, request_id)
        elif row.label != body.label:
            raise ApiError(409, "dataset_conflict", "Dataset identity conflicts")
        session.flush()
        return {"id": row.id, "label": row.label, "synthetic": True}


def ingest(
    session: Session, dataset_id: UUID, body: Ingest, key: str, request_id: str
) -> dict[str, Any]:
    serialized = [event.model_dump(mode="json") for event in body.events]
    # Order is transport detail. Repeated event identities in a batch are rejected.
    serialized.sort(key=lambda event: (event["source_id"], event["event_id"]))
    if len({(event["source_id"], event["event_id"]) for event in serialized}) != len(serialized):
        raise ApiError(422, "duplicate_batch_identity", "Batch identities must be distinct")
    request_digest = fingerprint({"version": body.version, "events": serialized})
    with session.begin():
        ready(session)
        dataset = session.scalar(select(Dataset).where(Dataset.id == dataset_id).with_for_update())
        if dataset is None:
            raise ApiError(404, "not_found", "Synthetic dataset not found")
        prior = session.scalar(
            select(CorrelationRun).where(
                CorrelationRun.dataset_id == dataset_id, CorrelationRun.idempotency_key == key
            )
        )
        if prior:
            if prior.request_digest != request_digest:
                raise ApiError(409, "idempotency_conflict", "Idempotency payload conflicts")
            return dict(prior.acceptance)
        existing = list(
            session.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.dataset_id == dataset_id)
                .order_by(SecurityEvent.id)
                .limit(1001)
            )
        )
        if (
            len(existing) > 1000
            or (
                session.scalar(
                    select(func.count())
                    .select_from(CorrelationRun)
                    .where(CorrelationRun.dataset_id == dataset_id)
                )
                or 0
            )
            >= 128
        ):
            raise ApiError(429, "soc_capacity", "Synthetic history quota reached")
        lookup = {(row.source_id, row.external_id): row for row in existing}
        newest = max((row.occurred_at for row in existing), default=None)
        now = Controller.now(session)
        added, duplicates, delayed, out_of_order = 0, 0, 0, 0
        for event, normalized in zip(
            sorted(body.events, key=lambda e: (e.source_id, e.event_id)), serialized, strict=True
        ):
            if event.occurred_at > now + timedelta(minutes=5):
                raise ApiError(422, "future_event", "Event timestamp is too far in the future")
            content_digest = fingerprint(normalized)
            previous = lookup.get((event.source_id, event.event_id))
            if previous:
                if previous.payload_digest != content_digest:
                    raise ApiError(409, "event_conflict", "Event identity payload conflicts")
                duplicates += 1
                continue
            identity = uuid5(
                NAMESPACE_URL, f"asp-soc-v1:{dataset_id}:{event.source_id}:{event.event_id}"
            )
            row = SecurityEvent(
                id=identity,
                dataset_id=dataset_id,
                source_id=event.source_id,
                external_id=event.event_id,
                occurred_at=event.occurred_at,
                ingested_at=now,
                payload_digest=content_digest,
                canonical=normalized,
            )
            session.add(row)
            existing.append(row)
            added += 1
            delayed += int(now - event.occurred_at > timedelta(hours=1))
            out_of_order += int(newest is not None and event.occurred_at < newest)
        if len(existing) > 1000:
            raise ApiError(429, "soc_capacity", "Synthetic event quota reached")
        run_id = uuid5(NAMESPACE_URL, f"asp-soc-run-v1:{dataset_id}:{key}")
        accepted = {
            "id": str(run_id),
            "dataset_id": str(dataset_id),
            "accepted": added,
            "duplicates": duplicates,
            "delayed": delayed,
            "out_of_order": out_of_order,
            "synthetic": True,
            "status_url": f"/api/v1/soc/runs/{run_id}",
        }
        run = CorrelationRun(
            id=run_id,
            dataset_id=dataset_id,
            idempotency_key=key,
            request_digest=request_digest,
            rules_digest=RULE_DIGEST,
            event_ids=sorted(str(row.id) for row in existing),
            acceptance=accepted,
        )
        session.add(run)
        session.flush()
        session.add(Job(run_id=run_id, request_id=request_id))
        audit(session, "events.accepted", run_id, request_id)
        return accepted


def event_read(row: SecurityEvent) -> dict[str, Any]:
    return {
        "id": row.id,
        "dataset_id": row.dataset_id,
        "source_id": row.source_id,
        "occurred_at": row.occurred_at,
        "ingested_at": row.ingested_at,
        "payload_digest": row.payload_digest,
        "canonical": row.canonical,
        "synthetic": True,
    }


def investigation_read(row: Investigation) -> dict[str, Any]:
    return {
        "id": row.id,
        "dataset_id": row.dataset_id,
        "run_id": row.run_id,
        "tracking_id": row.tracking_id,
        "rule_id": row.rule_id,
        "rule": RULES[row.rule_id],
        "evidence_state": row.evidence_state,
        "evidence": row.evidence,
        "revision": row.revision,
        "disposition": row.disposition,
        "created_at": row.created_at,
        "synthetic": True,
    }


def review(
    session: Session, investigation_id: UUID, body: ReviewWrite, request_id: str
) -> dict[str, Any]:
    with session.begin():
        ready(session)
        row = session.scalar(
            select(Investigation).where(Investigation.id == investigation_id).with_for_update()
        )
        if row is None:
            raise ApiError(404, "not_found", "Investigation not found")
        if row.revision != body.expected_revision:
            raise ApiError(409, "revision_conflict", "Reload the current analyst revision")
        if row.revision >= 1000:
            raise ApiError(429, "soc_capacity", "Analyst revision quota reached")
        row.revision += 1
        row.disposition = body.disposition
        session.add(
            AnalystFeedback(
                investigation_id=row.id,
                revision=row.revision,
                disposition=body.disposition,
                note=body.note,
                feedback=body.feedback,
            )
        )
        audit(session, "review.created", row.id, request_id)
        return investigation_read(row)


def retention(session: Session) -> dict[str, Any]:
    # Every accepted event is referenced by an immutable run. Do not delete history
    # or break replay identities. Full datasets fail admission until operator review.
    ready(session)
    old = session.scalar(
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.ingested_at < func.clock_timestamp() - text("interval '30 days'"))
    )
    return {
        "dry_run": True,
        "retention_days": 30,
        "old_events": old,
        "eligible_for_deletion": 0,
        "reason": "retained_run_and_replay_references",
        "dataset_limit": 32,
        "events_per_dataset": 1000,
        "runs_per_dataset": 128,
        "review_revisions_per_investigation": 1000,
    }
