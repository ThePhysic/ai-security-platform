from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ai_security_platform.api.dependencies import get_session
from ai_security_platform.api.security import bearer_scheme
from ai_security_platform.domain.errors import ApiError
from ai_security_platform.domain.scans import ScanRead
from ai_security_platform.storage.repositories import get_scan

router = APIRouter(prefix="/api/v1/scan-runs", dependencies=[Depends(bearer_scheme)])


@router.get("/{scan_id}", response_model=ScanRead)
def read_scan(scan_id: UUID, session: Annotated[Session, Depends(get_session)]) -> ScanRead:
    scan = get_scan(session, scan_id)
    if scan is None:
        raise ApiError(404, "not_found", "Scan not found")
    return ScanRead.model_validate(scan)
