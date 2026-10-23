"""Maintained synthetic data only; no repository scripts or live event acquisition."""

from datetime import UTC, datetime, timedelta

from ai_security_platform.soc.contracts import Ingest


def scenario(name: str) -> Ingest:
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    base = {
        "version": 1,
        "format": "identity-v1",
        "source_id": "synthetic-idp",
        "actor": "actor-demo",
        "session_id": "session-demo",
    }
    events = []
    if name == "auth-burst":
        for i in range(3):
            events.append(
                base
                | {
                    "event_id": f"event-failed-{i}",
                    "occurred_at": (moment + timedelta(seconds=i)).isoformat(),
                    "action": "authentication_failed",
                }
            )
        events.append(
            base
            | {
                "event_id": "event-success",
                "action": "authentication_succeeded",
                "occurred_at": (moment + timedelta(seconds=5)).isoformat(),
            }
        )
    elif name in {"session-grant", "incomplete"}:
        if name == "session-grant":
            events.append(
                base
                | {
                    "event_id": "event-success",
                    "action": "authentication_succeeded",
                    "occurred_at": moment.isoformat(),
                }
            )
        events.append(
            {
                "version": 1,
                "format": "cloud-iam-v1",
                "source_id": "synthetic-cloud",
                "event_id": "event-grant",
                "actor": "actor-demo",
                "session_id": "session-demo",
                "action": "admin_granted",
                "resource": "resource-demo",
                "occurred_at": (moment + timedelta(seconds=5)).isoformat(),
            }
        )
    elif name == "clean":
        events.append(
            base
            | {
                "event_id": "event-success",
                "action": "authentication_succeeded",
                "occurred_at": moment.isoformat(),
            }
        )
    else:
        raise ValueError("unknown_synthetic_scenario")
    return Ingest.model_validate({"events": events})
