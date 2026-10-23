"""Mounted only by explicit opt-in; existing local HTTP boundary applies unchanged."""

from datetime import datetime
from typing import Annotated, Any, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from ai_security_platform.api.dependencies import get_session
from ai_security_platform.api.pagination import pack_cursor, unpack_cursor
from ai_security_platform.api.security import bearer_scheme
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.soc.contracts import (
    RULE_DIGEST,
    RULES,
    DatasetCreate,
    Ingest,
    ReviewWrite,
)
from ai_security_platform.soc.models import (
    AnalystFeedback,
    CorrelationRun,
    Investigation,
    Job,
    SecurityEvent,
)
from ai_security_platform.soc.store import (
    create_dataset,
    event_read,
    ingest,
    investigation_read,
    ready,
    retention,
    review,
)

router = APIRouter(prefix="/api/v1/soc", dependencies=[Depends(bearer_scheme)])
Database = Annotated[Session, Depends(get_session)]
Limit = Annotated[int, Query(ge=1, le=100)]
Cursor = Annotated[str | None, Query(max_length=2048)]


@router.get("/rules")
def rules() -> dict[str, Any]:
    return {"version": 1, "rules_digest": RULE_DIGEST, "rules": RULES, "synthetic_only": True}


@router.post("/datasets", status_code=201)
def dataset(body: DatasetCreate, request: Request, session: Database) -> dict[str, Any]:
    return create_dataset(session, body, request.state.request_id)


@router.post("/datasets/{dataset_id}/events", status_code=202)
def accept(
    dataset_id: UUID,
    body: Ingest,
    request: Request,
    session: Database,
    key: Annotated[str, Header(alias="Idempotency-Key", pattern=r"^[A-Za-z0-9_.-]{1,128}$")],
) -> dict[str, Any]:
    if len(request.headers.getlist("idempotency-key")) != 1:
        raise ApiError(400, "invalid_idempotency_key", "One idempotency key is required")
    return ingest(session, dataset_id, body, key, request.state.request_id)


def page(
    session: Session,
    model: type[SecurityEvent] | type[Investigation],
    dataset_id: UUID,
    cursor: str | None,
    limit: int,
    request: Request,
) -> dict[str, Any]:
    ready(session)
    column = model.ingested_at if model is SecurityEvent else Investigation.created_at
    filters = {"scope": "soc-v1", "dataset_id": str(dataset_id), "table": model.__tablename__}
    secret = request.app.state.settings.api_token.get_secret_value()
    query = select(model).where(model.dataset_id == dataset_id)
    upper: tuple[datetime, UUID] | None = None
    if cursor:
        last, upper = unpack_cursor(cursor, filters, secret)
        query = query.where(tuple_(column, model.id) < last, tuple_(column, model.id) <= upper)
    rows = cast(
        list[SecurityEvent | Investigation],
        list(session.scalars(query.order_by(column.desc(), model.id.desc()).limit(limit + 1))),
    )
    if rows and upper is None:
        upper = (getattr(rows[0], column.key), rows[0].id)
    next_cursor = None
    if len(rows) > limit and upper:
        last_row = rows[limit - 1]
        next_cursor = pack_cursor(
            (getattr(last_row, column.key), last_row.id), upper, filters, secret
        )
    return {
        "items": [
            event_read(row) if isinstance(row, SecurityEvent) else investigation_read(row)
            for row in rows[:limit]
        ],
        "next_cursor": next_cursor,
    }


@router.get("/datasets/{dataset_id}/events")
def events(
    dataset_id: UUID, request: Request, session: Database, limit: Limit = 50, cursor: Cursor = None
) -> dict[str, Any]:
    return page(session, SecurityEvent, dataset_id, cursor, limit, request)


@router.get("/datasets/{dataset_id}/investigations")
def investigations(
    dataset_id: UUID, request: Request, session: Database, limit: Limit = 50, cursor: Cursor = None
) -> dict[str, Any]:
    return page(session, Investigation, dataset_id, cursor, limit, request)


@router.get("/runs/{run_id}")
def run_status(run_id: UUID, session: Database) -> dict[str, Any]:
    ready(session)
    row = session.get(CorrelationRun, run_id)
    if row is None:
        raise ApiError(404, "not_found", "Correlation run not found")
    job = session.scalars(select(Job).where(Job.run_id == row.id)).one()
    return {
        "id": row.id,
        "dataset_id": row.dataset_id,
        "status": row.status,
        "rules_digest": row.rules_digest,
        "input_events": len(row.event_ids),
        "created_at": row.created_at,
        "completed_at": row.completed_at,
        "coverage": "bounded_synthetic_correlation_only",
        "job_state": job.state,
        "attempts": job.attempts,
        "error_code": job.error_code,
    }


@router.get("/investigations/{investigation_id}")
def investigation(investigation_id: UUID, session: Database) -> dict[str, Any]:
    ready(session)
    row = session.get(Investigation, investigation_id)
    if row is None:
        raise ApiError(404, "not_found", "Investigation not found")
    return investigation_read(row)


@router.get("/investigations/{investigation_id}/timeline")
def timeline(investigation_id: UUID, session: Database) -> dict[str, Any]:
    ready(session)
    row = session.get(Investigation, investigation_id)
    if row is None:
        raise ApiError(404, "not_found", "Investigation not found")
    expected = {UUID(item["id"]): item for item in row.evidence}
    events = list(
        session.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.dataset_id == row.dataset_id, SecurityEvent.id.in_(expected))
            .order_by(SecurityEvent.occurred_at, SecurityEvent.id)
        )
    )
    if len(events) != len(expected) or any(
        event.payload_digest != expected[event.id]["payload_digest"]
        or event.occurred_at.isoformat() != expected[event.id]["occurred_at"]
        for event in events
    ):
        raise ApiError(503, "evidence_unavailable", "Matching event evidence is unavailable")
    return {
        "investigation_id": row.id,
        "run_id": row.run_id,
        "evidence_state": row.evidence_state,
        "items": [event_read(event) for event in events],
    }


@router.post("/investigations/{investigation_id}/review")
def write_review(
    investigation_id: UUID, body: ReviewWrite, request: Request, session: Database
) -> dict[str, Any]:
    return review(session, investigation_id, body, request.state.request_id)


@router.get("/investigations/{investigation_id}/review-history")
def review_history(
    investigation_id: UUID,
    session: Database,
    before_revision: Annotated[int | None, Query(ge=1)] = None,
    limit: Limit = 50,
) -> dict[str, Any]:
    ready(session)
    query = select(AnalystFeedback).where(AnalystFeedback.investigation_id == investigation_id)
    if before_revision:
        query = query.where(AnalystFeedback.revision < before_revision)
    rows = list(session.scalars(query.order_by(AnalystFeedback.revision.desc()).limit(limit + 1)))
    return {
        "items": [
            {
                "revision": row.revision,
                "disposition": row.disposition,
                "note": row.note,
                "feedback": row.feedback,
                "created_at": row.created_at,
            }
            for row in rows[:limit]
        ],
        "next_before_revision": rows[limit - 1].revision if len(rows) > limit else None,
    }


@router.get("/retention")
def retention_status(session: Database) -> dict[str, Any]:
    return retention(session)
