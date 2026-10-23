"""Bounded polling/pagination and scanner-only policy orchestration."""

import json
import math
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

from ai_security_platform.reporting.contracts import Report
from ai_security_platform.reporting.core import KNOWN_SECRET, encode, sarif
from ai_security_platform.reporting.files import write_artifact
from ai_security_platform.reporting.policy import Policy, evaluate
from ai_security_platform.snapshots.store import _check_ancestors

Client = Callable[..., dict[str, Any]]


def load_policy(path: Path | None) -> Policy:
    if path is None:
        return Policy()
    _check_ancestors(path.absolute())
    if not path.is_file() or path.stat().st_size > 4096:
        raise ValueError("invalid_policy")
    return Policy.model_validate_json(path.read_bytes())


def wait(
    client: Client, base: str, identifier: str, timeout: float, interval: float
) -> dict[str, Any]:
    if not (
        math.isfinite(timeout)
        and 0.1 <= timeout <= 900
        and math.isfinite(interval)
        and 0.1 <= interval <= 5
    ):
        raise ValueError("invalid_wait_limits")
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("wait_timeout_scan_continues")
        try:
            result = client(base, "/api/v1/scan-runs/" + identifier, timeout=min(10, remaining))
            state = result["status"]
            if state in {"succeeded", "partial", "failed"}:
                return result
            if state not in {"queued", "running"}:
                raise ValueError("invalid_scan_state")
        except HTTPError as error:
            if error.code not in {429, 502, 503, 504}:
                raise
        except (URLError, TimeoutError):
            pass
        time.sleep(min(interval, max(0, deadline - time.monotonic())))


def all_findings(
    client: Client, base: str, identifier: str, limit: int, max_pages: int
) -> dict[str, Any]:
    from urllib.parse import urlencode

    if not 1 <= limit <= 100 or not 1 <= max_pages <= 20:
        raise ValueError("invalid_pagination")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    cursors: set[str] = set()
    cursor = None
    for _ in range(max_pages):
        query = {"limit": str(limit)}
        if cursor:
            query["cursor"] = cursor
        page = client(base, "/api/v1/scan-runs/" + identifier + "/findings?" + urlencode(query))
        for row in page["items"]:
            if row["id"] in seen or len(rows) >= 1000:
                raise ValueError("pagination_limit_or_duplicate")
            seen.add(row["id"])
            rows.append(row)
        cursor = page["next_cursor"]
        if cursor is None:
            return {"items": rows, "next_cursor": None}
        if not isinstance(cursor, str) or cursor in cursors or len(cursor) > 2048:
            raise ValueError("invalid_cursor")
        cursors.add(cursor)
    raise ValueError("pagination_budget")


def finish(
    client: Client,
    base: str,
    identifier: str,
    policy: Policy,
    *,
    name: str | None = None,
    format: str = "json",
) -> tuple[dict[str, Any], int]:
    report = client(base, "/api/v1/scan-runs/" + identifier + "/export?format=json")
    Report.model_validate(report)
    if KNOWN_SECRET.search(json.dumps(report)):
        raise ValueError("unsafe_report")
    decision = evaluate(report, policy)
    result = {"scan_id": identifier, "scan_status": report["scan"]["status"], "policy": decision}
    if name is not None:
        document = report if format == "json" else sarif(report)
        result["artifact"] = write_artifact(Path.cwd(), name, format, encode(document))
    return result, decision["exit_code"]
