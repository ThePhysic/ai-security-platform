from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from ai_security_platform.config import Settings


def build_engine(settings: Settings) -> Engine:
    timeout = settings.database_timeout_seconds
    return create_engine(
        settings.database_url.get_secret_value(),
        echo=False,
        hide_parameters=True,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=0,
        pool_timeout=timeout,
        connect_args={
            "connect_timeout": timeout,
            "options": f"-c statement_timeout={timeout * 1000} -c lock_timeout=1000",
        },
    )


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
