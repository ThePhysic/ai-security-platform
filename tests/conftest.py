import io
import logging
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from ai_security_platform.api.app import create_app
from ai_security_platform.api.dependencies import get_session
from ai_security_platform.config import Settings

TOKEN = "synthetic-test-only-" + "a" * 48
SENSITIVE = "synthetic-never-disclose-" + "z" * 48


@pytest.fixture
def settings():
    return Settings(
        _env_file=None,
        database_url="postgresql+psycopg://unused:synthetic-password@127.0.0.1:1/unused",
        api_token=TOKEN,
        allowed_hosts=["localhost:8000", "127.0.0.1:8000"],
        allowed_origins=["http://localhost:8000"],
    )


@pytest.fixture
def logs():
    output = io.StringIO()
    logger = logging.getLogger("ai_security_platform")
    previous = logger.handlers[:]
    handler = logging.StreamHandler(output)
    logger.handlers[:] = [handler]
    yield output
    logger.handlers[:] = previous


@pytest.fixture
def app(settings):
    application = create_app(settings)
    session = MagicMock()
    application.dependency_overrides[get_session] = lambda: session
    return application


@pytest.fixture
def client(app, logs):
    with TestClient(app, base_url="http://localhost:8000") as connection:
        yield connection


@pytest.fixture
def auth():
    return {"Authorization": f"Bearer {TOKEN}"}
