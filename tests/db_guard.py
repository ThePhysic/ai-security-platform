"""Destructive tests never infer or reuse a developer database."""

from sqlalchemy.engine import make_url


def assert_disposable(url_text: str | None, marker: str | None) -> str:
    if not url_text or marker != "asp_phase1_test":
        raise RuntimeError("Explicit disposable test database configuration required")
    try:
        url = make_url(url_text)
        valid = (
            url.drivername == "postgresql+psycopg"
            and url.database == "asp_phase1_test"
            and url.username == "asp_test"
            and url.host in {"test-db", "127.0.0.1", "localhost"}
            and not url.query
        )
    except Exception:
        valid = False
    if not valid:
        raise RuntimeError("Refusing a database outside the disposable test identity")
    return url_text
