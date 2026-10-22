from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

from ai_security_platform.domain.errors import ApiError


class ErrorDetail(BaseModel):
    field: list[str]
    code: str


class ErrorResponse(BaseModel):
    code: str
    message: str
    request_id: str
    retryable: bool
    details: list[ErrorDetail]


def error_response(
    status: int,
    code: str,
    message: str,
    request_id: str,
    *,
    retryable: bool = False,
    details: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else {}
    return JSONResponse(
        status_code=status,
        headers=headers,
        content={
            "code": code,
            "message": message,
            "request_id": request_id,
            "retryable": retryable,
            "details": details or [],
        },
    )


def register_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Even field locations/types can contain attacker-defined dictionary keys.
        allowed_locations = {"body", "path", "query", "name", "id", "project_id", "scan_id"}
        details = [
            {
                "field": [
                    v if v in allowed_locations else "field" for v in e["loc"] if isinstance(v, str)
                ],
                "code": "invalid_value",
            }
            for e in exc.errors()[:10]
        ]
        return error_response(
            422, "validation_error", "Invalid request", request.state.request_id, details=details
        )

    @app.exception_handler(ApiError)
    async def domain_error(request: Request, exc: ApiError) -> JSONResponse:
        return error_response(
            exc.status, exc.code, exc.message, request.state.request_id, retryable=exc.retryable
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        return error_response(
            exc.status_code, "http_error", "Request could not be served", request.state.request_id
        )
