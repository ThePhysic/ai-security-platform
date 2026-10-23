import pytest
from pydantic import ValidationError

from ai_security_platform.config import ConfigurationError, Settings, load_settings
from ai_security_platform.domain.projects import ProjectCreate
from ai_security_platform.storage.base import Base
from tests.conftest import SENSITIVE, TOKEN

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "changes",
    [
        {"api_token": "short"},
        {"launcher_token": TOKEN},
        {"launcher_token": "short"},
        {"database_url": "sqlite://"},
        {"database_url": "postgresql+psycopg://u:p@localhost/db?sslmode=disable"},
        {"allowed_hosts": ["*"]},
        {"allowed_hosts": ["localhost:99999"]},
        {"allowed_origins": ["null"]},
        {"allowed_origins": ["http://localhost:8000/"]},
        {"allowed_origins": ["http://attacker.invalid:8000"]},
        {"request_body_limit": 1000000},
    ],
)
def test_reject_unsafe_settings(settings, changes):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **(settings.model_dump() | changes))


def test_settings_and_startup_do_not_disclose(settings, monkeypatch):
    assert TOKEN not in repr(settings)
    assert TOKEN not in settings.model_dump_json()
    monkeypatch.setenv("ASP_DATABASE_URL", SENSITIVE)
    monkeypatch.setenv("ASP_API_TOKEN", TOKEN)
    with pytest.raises(ConfigurationError) as exc:
        load_settings()
    assert SENSITIVE not in str(exc.value)


@pytest.mark.parametrize("name", ["", " ", "x" * 201, "bad\nname", "bad\x00name"])
def test_project_validation(name):
    with pytest.raises(ValidationError):
        ProjectCreate(name=name)


def test_normalization_and_extra_fields():
    assert ProjectCreate(name="  Example  ").name == "Example"
    with pytest.raises(ValidationError):
        ProjectCreate(name="Example", ignored_secret=SENSITIVE)


def test_only_approved_application_tables():
    from ai_security_platform.storage import models  # noqa: F401

    assert set(Base.metadata.tables) == {
        "projects",
        "source_snapshots",
        "scan_runs",
        "audit_events",
        "scanner_runs",
        "jobs",
        "job_attempts",
        "findings",
        "idempotency_requests",
        "scanner_invocations",
        "launcher_capabilities",
        "hosted_consents",
        "triage_runs",
        "triage_outcomes",
        "triage_provider_calls",
        "reviews",
        "review_revisions",
    }
