"""Pure deterministic rules over an explicit immutable set of normalized events."""

from datetime import datetime
from typing import Any

from ai_security_platform.soc.contracts import fingerprint


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not 1 <= len(events) <= 1000:
        raise ValueError("event_budget")
    events = sorted(events, key=lambda row: (row["occurred_at"], row["id"]))
    results = []
    for anchor in events:
        data = anchor["canonical"]
        rule, state, evidence = "", "matched", []
        if data["action"] == "authentication_succeeded":
            rule = "auth-burst-success-v1"
            preceding = [
                row
                for row in events
                if row["canonical"]["action"] == "authentication_failed"
                and row["canonical"]["actor"] == data["actor"]
                and 0 < seconds(anchor, row) <= 600
            ]
            if len(preceding) < 3:
                continue
            evidence = preceding[-20:] + [anchor]
        elif data["action"] == "admin_granted":
            rule = "session-admin-grant-v1"
            preceding = [
                row
                for row in events
                if row["canonical"]["action"] == "authentication_succeeded"
                and row["canonical"]["actor"] == data["actor"]
                and data["session_id"] is not None
                and row["canonical"]["session_id"] == data["session_id"]
                and 0 < seconds(anchor, row) <= 900
            ]
            evidence = preceding[-1:] + [anchor]
            if not preceding:
                state = "incomplete"
        else:
            continue
        results.append(
            {
                "tracking_id": fingerprint([rule, anchor["id"]]),
                "rule_id": rule,
                "evidence_state": state,
                "evidence": [
                    {key: row[key] for key in ("id", "payload_digest", "occurred_at")}
                    for row in evidence
                ],
            }
        )
    if len(results) > 200:
        raise ValueError("investigation_budget")
    return results


def seconds(later: dict[str, Any], earlier: dict[str, Any]) -> float:
    return (
        datetime.fromisoformat(later["occurred_at"])
        - datetime.fromisoformat(earlier["occurred_at"])
    ).total_seconds()
