from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ai_security_platform.agent.contracts import ConsentCreate, ReviewWrite, TriageSubmission
from ai_security_platform.agent.policy import configuration
from ai_security_platform.api.dependencies import get_session
from ai_security_platform.api.security import bearer_scheme
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.jobs.controller import Controller
from ai_security_platform.storage.intake import audit
from ai_security_platform.storage.models import Finding, HostedConsent, Review, ReviewRevision
from ai_security_platform.storage.triage import (
    accept_triage,
    create_consent,
    read_triage,
    review_read,
    write_review,
)

router = APIRouter(prefix="/api/v1", dependencies=[Depends(bearer_scheme)])
Database = Annotated[Session, Depends(get_session)]


@router.get("/triage-config")
def config(request: Request) -> dict[str, Any]:
    return {
        "offline": configuration("deterministic-v1"),
        "hosted": configuration("openai-v1"),
        "hosted_enabled": request.app.state.settings.hosted_enabled,
    }


@router.post("/findings/{finding_id}/triage", status_code=202)
def submit(
    finding_id: UUID,
    body: TriageSubmission,
    request: Request,
    response: Response,
    session: Database,
    key: Annotated[str, Header(alias="Idempotency-Key", pattern=r"^[A-Za-z0-9_.-]{1,128}$")],
) -> dict[str, Any]:
    if len(request.headers.getlist("idempotency-key")) != 1:
        raise ApiError(400, "invalid_idempotency_key", "One idempotency key is required")
    row = accept_triage(
        session, request.app.state.settings, finding_id, body, key, request.state.request_id
    )
    location = "/api/v1/triage-runs/" + str(row.id)
    response.headers["Location"] = location
    return {"id": row.id, "status": row.status, "status_url": location}


@router.get("/triage-runs/{triage_id}")
def read(triage_id: UUID, session: Database) -> dict[str, Any]:
    return read_triage(session, triage_id)


@router.post("/hosted-consents", status_code=201)
def consent(body: ConsentCreate, request: Request, session: Database) -> dict[str, Any]:
    row = create_consent(session, request.app.state.settings, body, request.state.request_id)
    return {
        "id": row.id,
        "operation_id": row.operation_id,
        "snapshot_id": row.snapshot_id,
        "manifest_digest": row.manifest_digest,
        "config_digest": row.config_digest,
        "data_categories": row.data_categories,
        "revoked": False,
    }


@router.delete("/hosted-consents/{consent_id}")
def revoke(consent_id: UUID, request: Request, session: Database) -> dict[str, bool]:
    with session.begin():
        row = session.scalar(
            select(HostedConsent).where(HostedConsent.id == consent_id).with_for_update()
        )
        if row is None:
            raise ApiError(404, "not_found", "Consent not found")
        if row.revoked_at is None:
            row.revoked_at = Controller.now(session)
            audit(session, "consent.revoked", "consent", row.id, request.state.request_id)
    return {"revoked": True}


@router.put("/findings/{finding_id}/review")
def put_review(
    finding_id: UUID, body: ReviewWrite, request: Request, session: Database
) -> dict[str, Any]:
    return write_review(session, finding_id, body, request.state.request_id)


@router.get("/findings/{finding_id}/review")
def get_review(finding_id: UUID, session: Database) -> dict[str, Any]:
    if session.get(Finding, finding_id) is None:
        raise ApiError(404, "not_found", "Finding not found")
    current = session.get(Review, finding_id)
    return (
        review_read(current)
        if current
        else {"finding_id": finding_id, "revision": 0, "disposition": None, "note": ""}
    )


@router.get("/findings/{finding_id}/review-revisions")
def history(
    finding_id: UUID,
    session: Database,
    before_revision: Annotated[int | None, Query(ge=1, le=2147483647)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    if session.get(Finding, finding_id) is None:
        raise ApiError(404, "not_found", "Finding not found")
    query = select(ReviewRevision).where(ReviewRevision.finding_id == finding_id)
    if before_revision is not None:
        query = query.where(ReviewRevision.revision < before_revision)
    rows = list(session.scalars(query.order_by(ReviewRevision.revision.desc()).limit(limit + 1)))
    return {
        "items": [
            review_read(row)
            | {
                "triage_run_id": row.triage_run_id,
                "feedback": row.feedback,
                "created_at": row.created_at,
            }
            for row in rows[:limit]
        ],
        "next_before_revision": rows[limit - 1].revision if len(rows) > limit else None,
    }
