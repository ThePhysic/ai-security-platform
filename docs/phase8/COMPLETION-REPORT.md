# Phase 8 completion

**8A PASS, 8B PASS, 8C PASS within the declared local synthetic scope.**
The optional extension is complete. It remains disabled by default, separately migrated
and independently removable. The AppSec flagship and its 1Password priority are preserved.

Implemented two versioned synthetic identity/cloud adapters, bounded canonical event
storage, deterministic identities, database-enforced request/event idempotency and durable
acceptance. Two deterministic correlation rules produce immutable evidence-linked run
occurrences, explicit incomplete evidence, stable tracking IDs, verified timelines and
paginated history. Analyst review has bounded redacted notes, feedback, optimistic
concurrency, immutable revisions and atomic audit events.

Separate PostgreSQL job/attempt targets reuse the established lease/fencing protocol and
shared ownership predicates. No Redis, queue service, live connector, scanner, model,
agent framework, SOC UI or automatic response was added. The module owns schema `soc`
and revision **soc_0001**; public schema/revision **0004_triage_review** is unchanged.
All runtime implementation lives under `soc/`, apart from a default-false setting,
conditional route mount and shared lease predicate extraction. See
[architecture/contracts](ARCHITECTURE-AND-CONTRACTS.md), [complete inventory](FILES.md),
[threat model](THREAT-MODEL.md), [scenarios](SCENARIOS.md) and [runbook](RUNBOOK.md).

## Observed acceptance evidence

- **319 backend tests passed**, zero failed/skipped, including 25 scan and five triage
  crash/retry experiments. Final affected suite: **209 passed**, zero failed/skipped.
- New SOC coverage: 19 unit/security cases and 14 real PostgreSQL cases; independent
  ingestion/claim/review processes, worker termination, DB disconnection, replay/conflict,
  late evidence, bounded retry exhaustion, schema removal and physical module removal.
- **31 actual scanner isolation**, **16 genuine scanner**, **10 native NTFS** and
  **15 selected Chromium** checks passed. Existing scanner admission stayed disabled.
- Isolated real CLI/API/worker demo: **9 checks**, four scenarios, 8 persisted events,
  4 runs, 3 investigations, one analyst revision; restart persistence and disabled routes.
- Fresh build: **4 checks**; final data/config/confidentiality/frozen-baseline audit:
  **17 checks**. Ruff/mypy/TypeScript/build pass. Counts overlap; no aggregate is implied.

The controlled 1,000-event query uses its intended history index; measured plan execution
was 0.054 ms in one warm local observation. AppSec 1/2/4-worker measurements and query
plans reran without changing indexes. These are local observations, not production
capacity or demonstrated improvements. [Full validation](VALIDATION.md) and
[commands](COMMANDS.md) identify genuine process/container tests versus offline/scripted
behavior and disclose corrected harness failures.

All 18 retained public/version-table fingerprints remain unchanged. Earlier phase reports,
frozen evaluation and scanner policy bytes, Python/npm locks and private instructions
remain unchanged. No actual local credential was found in public evidence/assets/logs.
Retained development was not SOC-migrated. The isolated demo and services started for
validation are stopped with data retained; real/hosted admission remains disabled.

## Versions, limits and deviations

No dependency changes. Python **3.12.15**, uv **0.13.5**, PostgreSQL **17.11**,
FastAPI **0.161.0**, Pydantic **2.14.1**, SQLAlchemy **2.0.55**, Alembic **1.20.1**,
Psycopg **3.3.6**. Node **24.22.1**; existing React/TypeScript/Vite/Playwright locks
unchanged. Exact runtime versions, image/asset identities and dependency checks appear
in [state](state-evidence.json), [build](rebuild-evidence.json) and scanner evidence.

No approved scope deviation or known unresolved Phase 8 blocker remains. Distinct SOC
job tables are necessary to preserve Phase 0's independent metadata/removal requirement;
they use the existing PostgreSQL execution protocol rather than a new infrastructure queue.
The optional development overlay was configuration-validated; actual runtime proof uses
the separate synthetic demo namespace. Main AppSec data was intentionally not migrated.

Limits: two fixed synthetic rules, no general detection quality claim or causal inference;
single trusted local operator/database owner; bounded quotas with conservative referenced
history retention; no dedicated SOC backup/restore proof; non-MVCC history traversal;
heuristic note redaction. Original A13 advisory-remediation, limited offline triage,
unsupported coverage and two ungraded Kubernetes bindings remain disclosed. The extension
does not alter those capabilities or frozen benchmark labels to improve scores.

Use the [runbook](RUNBOOK.md) to restart the isolated demo, disable SOC, recover expired
work or roll back code while preserving storage. Schema downgrade/removal was destructive
only in the guarded disposable test database. Do not downgrade or delete retained data
as routine rollback. Main AppSec startup remains independent through the Phase 7 runbook.

## Factual Prophet-oriented portfolio statements

- Implemented an optional PostgreSQL-backed synthetic identity/IAM ingestion module with
  database-enforced idempotency, bounded deterministic correlation and provenance-linked
  investigation timelines.
- Validated concurrent ingestion, SKIP LOCKED claims, fenced publication, worker/connection
  interruption recovery and optimistic analyst review using real PostgreSQL and separate
  processes; added 33 focused SOC unit/database cases to a 319-test backend suite.
- Demonstrated two positive, one clean and one incomplete synthetic investigation scenario,
  indexed 1,000-event history queries and independent module/schema disable/removal while
  preserving the existing AppSec platform.

These are local portfolio engineering results, not enterprise telemetry, production SLOs,
autonomous SOC reasoning, universal prevention or third-party certification.

Phase 8 ends here. No Matroid audit, live integration, deployment, Git write or subsequent
implementation is authorized or performed.
