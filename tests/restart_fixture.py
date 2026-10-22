"""Guarded test metadata, never a production scan or source acquisition."""

import json
import os

from sqlalchemy.orm import Session

from ai_security_platform.config import Settings
from ai_security_platform.storage.models import ScanRun
from ai_security_platform.storage.session import build_engine
from tests.conftest import TOKEN
from tests.db_guard import assert_disposable
from tests.postgres.test_database import snapshot_for

if __name__ == "__main__":
    url = assert_disposable(
        os.environ.get("TEST_DATABASE_URL"), os.environ.get("ASP_DISPOSABLE_TEST_DB")
    )
    engine = build_engine(Settings(_env_file=None, database_url=url, api_token=TOKEN))
    with Session(engine, expire_on_commit=False) as session, session.begin():
        project, snapshot = snapshot_for(session)
        scan = ScanRun(
            project_id=project.id,
            snapshot_id=snapshot.id,
            profile_id="test-only-physical-restart",
            profile_digest="d" * 64,
            status="queued",
        )
        session.add(scan)
        session.flush()
        print(json.dumps({"scan_id": str(scan.id)}))
    engine.dispose()
