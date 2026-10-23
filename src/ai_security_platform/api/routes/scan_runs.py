from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, tuple_
from sqlalchemy.orm import Session

from ai_security_platform.agent.contracts import Disposition
from ai_security_platform.api.dependencies import get_session
from ai_security_platform.api.pagination import pack_cursor, unpack_cursor
from ai_security_platform.api.security import bearer_scheme
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.domain.findings import FindingPage, FindingRead
from ai_security_platform.domain.intake import ScanAccepted, ScanSubmission
from ai_security_platform.domain.scans import ScannerRead, ScanPage, ScanRead, ScanStatus
from ai_security_platform.storage.intake import accept_scan
from ai_security_platform.storage.models import Finding, Review, ScannerRun, ScanRun
from ai_security_platform.storage.repositories import get_scan

router = APIRouter(prefix="/api/v1/scan-runs", dependencies=[Depends(bearer_scheme)])
Database = Annotated[Session, Depends(get_session)]


@router.post("", status_code=202, response_model=ScanAccepted)
def submit(
    body: ScanSubmission,
    request: Request,
    response: Response,
    session: Database,
    key: Annotated[str, Header(alias="Idempotency-Key", pattern=r"^[A-Za-z0-9_.-]{1,128}$")],
) -> ScanAccepted:
    if len(request.headers.getlist("idempotency-key")) != 1:
        raise ApiError(400, "invalid_idempotency_key", "One idempotency key is required")
    scan = accept_scan(session, request.app.state.settings, body, key, request.state.request_id)
    url = "/api/v1/scan-runs/" + str(scan.id)
    response.headers["Location"] = url
    return ScanAccepted(id=scan.id, status=scan.status, status_url=url)


@router.get("", response_model=ScanPage)
def history(
    project: UUID,
    request: Request,
    session: Database,
    status: ScanStatus | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> ScanPage:
    filters = {"kind": "scans", "project": str(project), "status": status}
    secret = request.app.state.settings.api_token.get_secret_value()
    query = select(ScanRun).where(ScanRun.project_id == project)
    if status is not None:
        query = query.where(ScanRun.status == status.value)
    if cursor:
        last, upper = unpack_cursor(cursor, filters, secret)
        query = query.where(tuple_(ScanRun.created_at, ScanRun.id) < last)
    else:
        now = session.scalar(select(func.clock_timestamp()))
        assert isinstance(now, datetime)
        upper = (now.astimezone(UTC), UUID(int=(1 << 128) - 1))
    query = (
        query.where(tuple_(ScanRun.created_at, ScanRun.id) <= upper)
        .order_by(ScanRun.created_at.desc(), ScanRun.id.desc())
        .limit(limit + 1)
    )
    rows = list(session.scalars(query))
    items = rows[:limit]
    next_cursor = (
        pack_cursor((items[-1].created_at, items[-1].id), upper, filters, secret)
        if len(rows) > limit
        else None
    )
    return ScanPage(items=[ScanRead.model_validate(row) for row in items], next_cursor=next_cursor)


@router.get("/{scan_id}", response_model=ScanRead)
def read_scan(scan_id: UUID, session: Database) -> ScanRead:
    scan = get_scan(session, scan_id)
    if scan is None:
        raise ApiError(404, "not_found", "Scan not found")
    result = ScanRead.model_validate(scan)
    stages = session.scalars(
        select(ScannerRun).where(ScannerRun.scan_run_id == scan_id).order_by(ScannerRun.scanner_id)
    )
    result.scanner_runs = [ScannerRead.model_validate(stage) for stage in stages]
    return result


@router.get("/{scan_id}/findings", response_model=FindingPage)
def findings(
    scan_id: UUID,
    request: Request,
    session: Database,
    severity: Literal["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    scanner: Annotated[str | None, Query(pattern=r"^[a-z0-9-]{1,32}$")] = None,
    rule_id: Annotated[str | None, Query(max_length=128)] = None,
    review: Disposition | Literal["unreviewed"] | None = None,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> FindingPage:
    if session.get(ScanRun, scan_id) is None:
        raise ApiError(404, "not_found", "Scan not found")
    filters = {
        "kind": "findings",
        "scan": str(scan_id),
        "severity": severity,
        "scanner": scanner,
        "rule_id": rule_id,
    }
    secret = request.app.state.settings.api_token.get_secret_value()
    query = select(Finding).where(Finding.scan_run_id == scan_id)
    if review is not None:
        filters["review"] = review
        query = query.outerjoin(Review, Review.finding_id == Finding.id)
        query = query.where(
            Review.finding_id.is_(None) if review == "unreviewed" else Review.disposition == review
        )
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if scanner is not None:
        query = query.join(ScannerRun, Finding.scanner_run_id == ScannerRun.id).where(
            ScannerRun.scanner_id == scanner
        )
    if rule_id is not None:
        query = query.where(Finding.rule_id == rule_id)
    if cursor:
        last, upper = unpack_cursor(cursor, filters, secret)
        query = query.where(tuple_(Finding.created_at, Finding.id) < last)
    else:
        now = session.scalar(select(func.clock_timestamp()))
        assert isinstance(now, datetime)
        upper = (now.astimezone(UTC), UUID(int=(1 << 128) - 1))
    rows = list(
        session.scalars(
            query.where(tuple_(Finding.created_at, Finding.id) <= upper)
            .order_by(Finding.created_at.desc(), Finding.id.desc())
            .limit(limit + 1)
        )
    )
    items = rows[:limit]
    next_cursor = (
        pack_cursor((items[-1].created_at, items[-1].id), upper, filters, secret)
        if len(rows) > limit
        else None
    )
    return FindingPage(
        items=[FindingRead.model_validate(row) for row in items], next_cursor=next_cursor
    )


@router.get("/{scan_id}/export")
def export_json(
    scan_id: UUID,
    session: Database,
    format: Literal["json"] = "json",
) -> JSONResponse:
    scan = read_scan(scan_id, session)
    rows = list(
        session.scalars(
            select(Finding)
            .where(Finding.scan_run_id == scan_id)
            .order_by(Finding.created_at, Finding.id)
            .limit(1001)
        )
    )
    if len(rows) > 1000:
        raise ApiError(409, "export_limit", "Use paginated findings for this scan")
    return JSONResponse(
        {
            "schema_version": 1,
            "scan": scan.model_dump(mode="json"),
            "findings": [FindingRead.model_validate(row).model_dump(mode="json") for row in rows],
        },
        headers={"Content-Disposition": f'attachment; filename="asp-scan-{scan_id}.json"'},
    )
