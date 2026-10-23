"""Pure ASGI request boundary, with bounded buffering before parsing."""

import asyncio
import hmac
import re
import time
from uuid import uuid4

from fastapi.security import HTTPBearer
from sqlalchemy.exc import OperationalError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ai_security_platform.api.errors import error_response
from ai_security_platform.config import Settings
from ai_security_platform.logging import log_request

bearer_scheme = HTTPBearer(auto_error=False)


class BoundaryMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.monotonic()
        request_id = str(uuid4())
        status = 500
        started = False
        headers: dict[bytes, list[bytes]] = {}
        for key, value in scope["headers"]:
            headers.setdefault(key.lower(), []).append(value)
        supplied_ids = headers.get(b"x-request-id", [])
        if len(supplied_ids) == 1 and re.fullmatch(rb"[A-Za-z0-9_-]{1,64}", supplied_ids[0]):
            request_id = supplied_ids[0].decode("ascii")
        scope.setdefault("state", {})["request_id"] = request_id
        origin_values = headers.get(b"origin", [])
        origin = origin_values[0].decode("latin1") if len(origin_values) == 1 else None
        cors_allowed = origin is not None and origin in self.settings.allowed_origins

        async def safe_send(message: Message) -> None:
            nonlocal status, started
            if message["type"] == "http.response.start":
                status = message["status"]
                started = True
                message["headers"] = list(message.get("headers", [])) + [
                    (b"x-request-id", request_id.encode("ascii")),
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                ]
                if cors_allowed:
                    assert origin is not None
                    message["headers"] += [
                        (b"access-control-allow-origin", origin.encode("ascii")),
                        (b"vary", b"Origin"),
                    ]
            await send(message)

        async def reject(code: int, category: str, message: str) -> None:
            await error_response(code, category, message, request_id)(scope, receive, safe_send)

        try:
            host_values = headers.get(b"host", [])
            if len(host_values) != 1 or host_values[0].decode("latin1") not in (
                self.settings.allowed_hosts
            ):
                await reject(400, "host_denied", "Host is not allowed")
                return
            if origin_values and (len(origin_values) != 1 or not cors_allowed):
                await reject(403, "origin_denied", "Origin is not allowed")
                return
            internal = scope["path"].startswith("/internal/v1/launcher")
            if internal and origin_values:
                await reject(403, "origin_denied", "Origin is not allowed")
                return
            if scope["method"] == "OPTIONS" and origin_values:
                methods = headers.get(b"access-control-request-method", [])
                requested = headers.get(b"access-control-request-headers", [])
                header_names = (
                    {h.strip().lower() for h in requested[0].decode("latin1").split(",")}
                    if len(requested) == 1
                    else set()
                )
                if (
                    len(methods) != 1
                    or methods[0] not in {b"GET", b"POST"}
                    or len(requested) > 1
                    or not header_names
                    <= {"authorization", "content-type", "x-request-id", "idempotency-key"}
                ):
                    await reject(403, "preflight_denied", "Preflight is not allowed")
                    return
                await safe_send(
                    {
                        "type": "http.response.start",
                        "status": 204,
                        "headers": [
                            (b"access-control-allow-methods", b"GET, POST"),
                            (
                                b"access-control-allow-headers",
                                b"authorization, content-type, x-request-id, idempotency-key",
                            ),
                        ],
                    }
                )
                await safe_send({"type": "http.response.body", "body": b""})
                return
            public = scope["method"] == "GET" and scope["path"] in {"/health", "/ready"}
            auth = headers.get(b"authorization", [])
            if any(len(v) > self.settings.authorization_header_limit for v in auth):
                await reject(413, "header_too_large", "Authorization header exceeds limit")
                return
            if not public:
                token = self.settings.launcher_token if internal else self.settings.api_token
                expected = (
                    b"Bearer " + token.get_secret_value().encode("ascii")
                    if token is not None
                    else b""
                )
                if token is None or len(auth) != 1 or not hmac.compare_digest(auth[0], expected):
                    await reject(401, "unauthorized", "Bearer authentication required")
                    return
            body_limit = (
                524288
                if scope["path"].endswith("/result") and internal
                else self.settings.request_body_limit
            )
            lengths = headers.get(b"content-length", [])
            if lengths:
                if len(lengths) != 1 or not re.fullmatch(rb"[0-9]{1,12}", lengths[0]):
                    await reject(400, "invalid_length", "Invalid request length")
                    return
                if int(lengths[0]) > body_limit:
                    await reject(413, "body_too_large", "Request body exceeds limit")
                    return
            if lengths and b"transfer-encoding" in headers:
                await reject(400, "ambiguous_length", "Ambiguous request length")
                return
            body = bytearray()
            async with asyncio.timeout(self.settings.body_timeout_seconds):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    if message["type"] != "http.request":
                        continue
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > body_limit:
                        await reject(413, "body_too_large", "Request body exceeds limit")
                        return
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
            delivered = False

            async def replay() -> Message:
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, replay, safe_send)
        except TimeoutError:
            if not started:
                await reject(408, "request_timeout", "Request body timed out")
        except OperationalError:
            if not started:
                await error_response(
                    503, "dependency_unavailable", "Service unavailable", request_id, retryable=True
                )(scope, receive, safe_send)
        except Exception:
            # Never rethrow into Uvicorn's raw traceback/access logging path.
            if not started:
                await reject(500, "internal_error", "Request could not be completed")
        finally:
            route = scope.get("route")
            template = getattr(route, "path", "unmatched")
            log_request(
                request_id,
                scope["method"],
                template,
                status,
                int((time.monotonic() - start) * 1000),
            )
