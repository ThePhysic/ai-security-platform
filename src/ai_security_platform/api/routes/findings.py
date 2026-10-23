from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ai_security_platform.api.dependencies import get_session
from ai_security_platform.api.security import bearer_scheme
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.domain.findings import FindingRead
from ai_security_platform.storage.models import Finding, ScannerRun, ScanRun, SourceSnapshot

router = APIRouter(prefix="/api/v1/findings", dependencies=[Depends(bearer_scheme)])
Database = Annotated[Session, Depends(get_session)]


@router.get("/{finding_id}")
def detail(finding_id: UUID, session: Database) -> dict[str, Any]:
    row = session.execute(
        select(Finding, ScannerRun, ScanRun, SourceSnapshot)
        .join(ScannerRun, Finding.scanner_run_id == ScannerRun.id)
        .join(ScanRun, Finding.scan_run_id == ScanRun.id)
        .join(SourceSnapshot, ScanRun.snapshot_id == SourceSnapshot.id)
        .where(Finding.id == finding_id)
    ).first()
    if row is None:
        raise ApiError(404, "not_found", "Finding not found")
    finding, scanner, scan, snapshot = row
    return {
        "finding": FindingRead.model_validate(finding).model_dump(mode="json"),
        "scanner_id": scanner.scanner_id,
        "coverage": scanner.coverage,
        "provenance": scanner.provenance,
        "snapshot_id": str(snapshot.id),
        "manifest_digest": snapshot.manifest_digest,
        "scan_status": scan.status,
    }
