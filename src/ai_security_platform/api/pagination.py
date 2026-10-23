import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from ai_security_platform.domain.errors import ApiError
from ai_security_platform.snapshots.policy import canonical, digest


def filter_hash(filters: dict[str, Any]) -> str:
    return digest(canonical(filters))


def pack_cursor(
    last: tuple[datetime, UUID], upper: tuple[datetime, UUID], filters: dict[str, Any], secret: str
) -> str:
    body = canonical(
        {
            "v": 1,
            "last": [last[0].isoformat(), str(last[1])],
            "upper": [upper[0].isoformat(), str(upper[1])],
            "filters": filter_hash(filters),
        }
    )
    encoded = base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")
    signature = hmac.new(
        secret.encode(), b"cursor-v1:" + encoded.encode(), hashlib.sha256
    ).hexdigest()
    return encoded + "." + signature


def unpack_cursor(
    value: str, filters: dict[str, Any], secret: str
) -> tuple[tuple[datetime, UUID], tuple[datetime, UUID]]:
    try:
        if len(value) > 2048:
            raise ValueError
        encoded, signature = value.split(".")
        expected = hmac.new(
            secret.encode(), b"cursor-v1:" + encoded.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        body = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if body["v"] != 1 or body["filters"] != filter_hash(filters):
            raise ValueError
        pairs = []
        for key in ("last", "upper"):
            moment = datetime.fromisoformat(body[key][0])
            if moment.tzinfo is None:
                raise ValueError
            pairs.append((moment.astimezone(UTC), UUID(body[key][1])))
        if pairs[0] > pairs[1]:
            raise ValueError
        return pairs[0], pairs[1]
    except (ValueError, KeyError, TypeError, IndexError, UnicodeError):
        raise ApiError(400, "invalid_cursor", "Cursor is invalid for this query") from None
