"""Optional version table and DDL live entirely inside schema soc."""

from alembic import context
from sqlalchemy import text

from ai_security_platform.config import load_settings
from ai_security_platform.soc.models import Base
from ai_security_platform.storage.session import build_engine


def run() -> None:
    settings = load_settings()
    if not settings.soc_enabled or context.is_offline_mode():
        raise RuntimeError("SOC migrations require explicit local opt-in")
    engine = build_engine(settings)
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE SCHEMA IF NOT EXISTS soc"))
            context.configure(
                connection=connection,
                target_metadata=Base.metadata,
                version_table_schema="soc",
                include_schemas=True,
                include_name=lambda name, kind, parents: kind != "schema" or name == "soc",
            )
            context.run_migrations()
    finally:
        engine.dispose()


try:
    run()
except Exception:
    raise RuntimeError("SOC migration failed; check opt-in and schema compatibility") from None
