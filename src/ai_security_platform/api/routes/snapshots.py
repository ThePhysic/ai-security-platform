from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ai_security_platform.api.dependencies import get_session
from ai_security_platform.api.security import bearer_scheme
from ai_security_platform.domain.intake import SnapshotRead, SnapshotRegistration
from ai_security_platform.storage.intake import register_snapshot

router = APIRouter(prefix="/api/v1/source-snapshots", dependencies=[Depends(bearer_scheme)])


@router.post("", status_code=201, response_model=SnapshotRead)
def register(
    body: SnapshotRegistration, request: Request, session: Annotated[Session, Depends(get_session)]
) -> SnapshotRead:
    snapshot = register_snapshot(
        session,
        request.app.state.snapshot_store,
        request.app.state.settings,
        body,
        request.state.request_id,
    )
    return SnapshotRead(
        id=snapshot.id,
        project_id=snapshot.project_id,
        snapshot_key=snapshot.spool_key,
        manifest_digest=snapshot.manifest_digest,
        content_digest=snapshot.content_digest,
        file_count=snapshot.file_count,
        byte_count=snapshot.byte_count,
        expires_at=snapshot.expires_at,
    )
