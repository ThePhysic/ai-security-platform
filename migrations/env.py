"""Explicit migrations with sanitized failures and no connection URL in config."""

from alembic import context

from ai_security_platform.config import load_settings
from ai_security_platform.storage.models import Base
from ai_security_platform.storage.session import build_engine

target_metadata = Base.metadata


def run() -> None:
    settings = load_settings()
    if context.is_offline_mode():
        context.configure(
            dialect_name="postgresql",
            target_metadata=target_metadata,
            literal_binds=True,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = build_engine(settings)
    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection, target_metadata=target_metadata, compare_type=True
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


try:
    run()
except Exception:
    raise RuntimeError("Migration failed; check database and schema compatibility") from None
