from fastapi import APIRouter, Request

from ai_security_platform.domain.errors import ApiError

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def ready(request: Request) -> dict[str, str]:
    status = request.app.state.readiness.check(
        request.app.state.engine, request.app.state.settings.database_timeout_seconds
    )
    if status != "ready":
        raise ApiError(503, status, "Service unavailable", retryable=True)
    return {"status": "ready"}
