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
        for model in MODEL_ORDER:
            session.execute(delete(model))
        session.commit()
        yield session
        session.rollback()
        for model in MODEL_ORDER:
            session.execute(delete(model))
        session.commit()
