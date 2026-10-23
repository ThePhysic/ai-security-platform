# Synthetic scenarios and evidence interpretation

Version: `soc-scenarios-v1`. Fixtures are maintained Python data constructors in
`soc/scenarios.py`; only the trusted fixture generator is executed. There are no target
repository scripts, package installs, live events, personal data or actual credentials.

All example event times begin at 2026-01-01T00:00:00Z. They deliberately exercise delayed
ingestion. Actor/session/resource labels are synthetic and shared only within one dataset.

| Scenario | Input | Independent expected label |
| --- | --- | --- |
| auth-burst | Failures at 0/1/2 seconds, success at 5 seconds, same actor | One auth-burst matched investigation; four event references |
| session-grant | Success at 0 seconds, admin grant at 5 seconds, exact actor/session | One session-admin-grant matched investigation; two references |
| clean | One successful authentication | No investigation under either selected rule; no global benign/security claim |
| incomplete | Admin grant without matching authentication | One explicitly incomplete investigation; one reference |

Late-arrival validation first processes an isolated grant and preserves its incomplete
investigation. A later batch supplies the earlier authentication: the new run matches,
the old evidence stays unchanged, and both occurrences share the anchor tracking ID.
Reverse-order input produces the same pure correlation result. Different actor, missing
session or outside-window events cannot substitute for the required relationship.

The labels describe these two explicit predicates, not scanner findings, maliciousness
or general detection precision/recall. The Phase 4 AppSec corpus, labels, two ungraded
Kubernetes bindings and A13 advisory-remediation limitation remain unchanged.

[Environment evidence](environment-evidence.json) records actual CLI/API/worker execution,
replay, review and container restart. [PostgreSQL evidence](soc-postgres-evidence.json)
records independent-process recovery and the controlled 1,000-event history plan.
Unit-test determinism is distinct from real process/database validation.
