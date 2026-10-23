"""Independent triage process. Provider failures never mutate scanner state."""

import signal
from contextlib import suppress
from threading import Event, Thread

from sqlalchemy.exc import SQLAlchemyError

from ai_security_platform.agent.contracts import Assessment
from ai_security_platform.agent.engine import Investigation, investigate
from ai_security_platform.agent.policy import AgentError
from ai_security_platform.agent.providers import DeterministicProvider, OpenAIProvider, Provider
from ai_security_platform.agent.tools import EvidenceTools
from ai_security_platform.config import load_settings
from ai_security_platform.jobs.controller import Lease, LeaseLost
from ai_security_platform.jobs.triage import TriageController
from ai_security_platform.jobs.worker import HeartbeatUncertain
from ai_security_platform.snapshots.store import SnapshotStore
from ai_security_platform.storage.models import TriageRun
from ai_security_platform.storage.readiness import DatabaseReadiness
from ai_security_platform.storage.session import build_engine, session_factory


def execute_triage(
    controller: TriageController,
    lease: Lease,
    store: SnapshotStore,
    provider: Provider | None = None,
) -> None:
    stop, lost = Event(), Event()

    def heartbeat() -> None:
        while not stop.wait(controller.settings.heartbeat_seconds):
            try:
                if controller.heartbeat(lease):
                    continue
            except SQLAlchemyError:
                pass
            lost.set()
            return

    thread = Thread(target=heartbeat, daemon=True, name="triage-heartbeat")
    thread.start()
    try:
        with controller.factory() as session:
            run = session.get(TriageRun, lease.triage_run_id)
            if run is None:
                raise AgentError("evidence_unavailable")
            selected_provider = run.provider
        if selected_provider == "openai-v1" and not controller.settings.hosted_enabled:
            raise AgentError("consent_denied")
        provider = provider or (
            OpenAIProvider.from_environment()
            if selected_provider == "openai-v1"
            else DeterministicProvider()
        )
        if provider.hosted != (selected_provider == "openai-v1"):
            raise AgentError("configuration_changed")
        tools = EvidenceTools(controller.factory, store, lease.triage_run_id)  # type: ignore[arg-type]

        def authorize(sequence: int, cost: int, tokens: int = 0) -> None:
            if lost.is_set():
                raise LeaseLost("lease_lost")
            controller.authorize(lease, sequence, cost, tokens)

        result = investigate(provider, tools, authorize)
        if not lost.is_set():
            controller.finish_triage(lease, result, tools)
    except LeaseLost:
        pass
    except AgentError as error:
        if not lost.is_set():
            with suppress(LeaseLost):
                if error.code == "evidence_unavailable":
                    abstention = Assessment(
                        assessment="abstain",
                        confidence=0,
                        summary=(
                            "Immutable source evidence is unavailable; no source substitution "
                            "was made."
                        ),
                        remediation=(
                            "Restore the matching authorized snapshot or request human "
                            "investigation."
                        ),
                        reason="source_unavailable",
                        citations=[],
                    )
                    controller.finish_triage(
                        lease, Investigation(abstention, [], {"billing_measured": False}), None
                    )
                else:
                    controller.fail(lease, error.code, permanent=not error.retryable)
        if error.restart:
            raise HeartbeatUncertain("provider_unavailable") from None
    except (ValueError, KeyError, TypeError):
        if not lost.is_set():
            with suppress(LeaseLost):
                controller.fail(lease, "invalid_provider_output", permanent=True)
    finally:
        stop.set()
        thread.join(timeout=controller.settings.database_timeout_seconds + 2)
        if thread.is_alive():
            raise HeartbeatUncertain("heartbeat_unavailable")


def main() -> None:
    settings = load_settings()
    engine = build_engine(settings)
    controller, stop, readiness = (
        TriageController(session_factory(engine), settings),
        Event(),
        DatabaseReadiness(),
    )
    store = SnapshotStore(settings.snapshot_spool)
    for name in (signal.SIGINT, signal.SIGTERM):
        signal.signal(name, lambda *_: stop.set())
    try:
        while not stop.is_set():
            try:
                if (
                    not settings.triage_enabled
                    or readiness.check(engine, settings.database_timeout_seconds) != "ready"
                ):
                    stop.wait(settings.poll_seconds)
                    continue
                controller.recover_one()
                lease = controller.claim()
                if lease is not None:
                    execute_triage(controller, lease, store)
                    continue
            except SQLAlchemyError:
                pass
            except HeartbeatUncertain:
                stop.set()
            stop.wait(settings.poll_seconds)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
