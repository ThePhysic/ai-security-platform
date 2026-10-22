"""Only constructed, allowlisted events reach this logger."""

import json
import logging
import sys


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("ai_security_platform")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def log_request(request_id: str, method: str, route: str, status: int, duration_ms: int) -> None:
    # No user strings other than a validated request ID; route comes from registered routing.
    event = {
        "event": "http_request",
        "request_id": request_id,
        "method": method
        if method in {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}
        else "OTHER",
        "route": route,
        "status": status,
        "duration_ms": duration_ms,
    }
    configure_logging().info(json.dumps(event, ensure_ascii=True))
