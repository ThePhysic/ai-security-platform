import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, text
from sqlalchemy.orm import Session

from ai_security_platform.config import Settings
from ai_security_platform.storage.models import (
    AuditEvent,
    Finding,
    IdempotencyRequest,
    Job,
    JobAttempt,
    LauncherCapability,
    Project,
    ScannerInvocation,
    ScannerRun,
    ScanRun,
    SourceSnapshot,
)
from ai_security_platform.storage.session import build_engine
from tests.conftest import TOKEN
from tests.db_guard import assert_disposable

ROOT = Path(__file__).resolve().parents[2]
MODEL_ORDER = (
    LauncherCapability,
    ScannerInvocation,
    IdempotencyRequest,
    Finding,
    JobAttempt,
    Job,
    ScannerRun,
    AuditEvent,
    ScanRun,
    SourceSnapshot,
    Project,
)


@pytest.fixture(scope="session")
def pg_runtime():
    url = assert_disposable(
        os.environ.get("TEST_DATABASE_URL"), os.environ.get("ASP_DISPOSABLE_TEST_DB")
    )
    settings = Settings(_env_file=None, database_url=url, api_token=TOKEN)
    engine = build_engine(settings)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT current_database(), current_user")).one() == (
            "asp_phase1_test",
            "asp_test",
        )
    patch = pytest.MonkeyPatch()
    patch.setenv("ASP_DATABASE_URL", url)
    patch.setenv("ASP_API_TOKEN", TOKEN)
    config = Config(str(ROOT / "alembic.ini"))
    command.upgrade(config, "head")
    yield engine, config, settings
    engine.dispose()
    patch.undo()


@pytest.fixture
def pg_session(pg_runtime):
    engine, _, _ = pg_runtime
    with Session(engine, expire_on_commit=False) as session:
        clear_triage(session)
        for model in MODEL_ORDER:
            session.execute(delete(model))
        session.commit()
        yield session
        session.rollback()
        clear_triage(session)
        for model in MODEL_ORDER:
            session.execute(delete(model))
        session.commit()


def clear_triage(session):
    # Runtime fixture already verifies the exact disposable database/user.
    # TRUNCATE is deliberately used only here; DELETE/UPDATE history remain denied.
    session.execute(text("TRUNCATE review_revisions"))
    for table in ("triage_provider_calls", "triage_outcomes", "reviews", "idempotency_requests"):
        session.execute(text("DELETE FROM " + table))
    session.execute(
        text(
            "DELETE FROM job_attempts WHERE job_id IN (SELECT id FROM jobs "
            "WHERE operation='triage')"
        )
    )
    session.execute(text("DELETE FROM jobs WHERE operation='triage'"))
    session.execute(text("DELETE FROM triage_runs"))
    session.execute(text("DELETE FROM hosted_consents"))
