# Phase 7 completion report

Completed **2026-10-23 (America/Los_Angeles)**; validation began October 22.
The flagship remains a local AppSec/developer-guardrails product, prioritizing 1Password
Junior Security Engineer evidence with supporting Brain Co AI-security and Prophet backend
reliability overlap. No optional SOC or separate Matroid implementation was performed.

| Checkpoint / milestone | Determination | Declared scope |
| --- | --- | --- |
| 7A final review and hardening | PASS | Finished threat model, four verified hardening fixes, locked build/supply-chain review and documented residual findings |
| 7B retention and matched recovery | PASS | Reference-aware inspection/controlled orphan cleanup, quotas/private backups, corruption rejection and two isolated matched restores |
| 7C rebuild, operations and demonstration | PASS | Fresh application/frontend build, actual clean services, offline CI artifacts, genuine controlled demo and complete applicable regressions |
| G10 | PASS locally | Actual Windows NTFS, Docker Desktop Linux, PostgreSQL, Chromium and deterministic/mocked-provider validation; no required blocked/skipped check |
| M4 | PASS within this local trust model | Complete flagship milestone; no production deployment, remote release or subsequent-phase authorization implied |

## Deliverables and exact changes

[FILES.md](FILES.md) lists all **16 modified / 73 created** public files and their purposes, plus ignored
private outputs. The implementation adds a narrow trusted-host maintenance CLI and test
tooling; it does not add a service or HTTP maintenance capability.

- Hardened staging/orphan removal with complete bounded no-follow preflight and pinned
  NTFS handles / POSIX relative deletion. Registered source/history is always preserved.
- Added default dry-run retention, explicit eligible-orphan apply, storage visibility,
  backup count/payload/row/dump bounds and private disposable restore instances.
- Added serialized report storage quotas while preserving atomic exclusive/no-overwrite
  publication and existing JSON/SARIF schemas/policy exit behavior.
- Pinned isolated hatchling build resolution and all five transitive build dependencies
  to exact versions and official wheel hashes in pyproject/uv.lock. Runtime versions unchanged.
- Added final threat review, reproducible evidence, safe runbooks, controlled demo, portfolio
  statements and current README/project-brief status. Historical phase reports remain unchanged.

There are **no new API endpoints, response/schema changes or Alembic migrations**.
Revision remains **0004_triage_review**. API/agent/scanner/queue/human-review logic, trusted
scanner policies, frozen evaluation labels and frontend application behavior are unchanged.
Frontend test tooling only selects separate Phase 7 evidence and a clean preview context.

## Architecture and findings

The [final architecture](ARCHITECTURE.md) preserves synchronous DB handlers and separate
durable workers. Only the trusted host launcher controls scanner containers. Maintenance
controls fixed local database/Compose resources from the trusted operator boundary; it is
unreachable from API, workers, scanners and model tools.

[FINDINGS.md](FINDINGS.md) records severity, boundary, impact, reproduction and mitigation.
The cleanup link/substitution gap, isolated build-lock gap and unbounded aggregate export
storage were corrected. The new disposable-worker launcher-capability inheritance was
also removed before final signoff; established development workers were unaffected. The broad OSV Trivy advisory match is retained and reviewed against
upstream affected versions. No known unaddressed high-severity defect was established in
the intended local trust model. This is not certification or an exhaustive scanner-image audit.

[Supply-chain evidence](supply-chain-evidence.json) covers 50 public package-version queries,
official pinned CI commits, scanner image/DB identity and build/npm lock practices.
The scoped npm audit reports zero advisories; the Python/scanner query has one reviewed
Trivy range match. No private source or credentials were transmitted during metadata review.

## Versions and provenance

Python **3.12.15**, uv **0.13.5**, PostgreSQL **17.11**, Docker Linux engine **29.9.1**,
Compose **5.6.0**. FastAPI **0.161.0**, Pydantic **2.14.1**, SQLAlchemy **2.0.55**,
Alembic **1.20.1**, Psycopg **3.3.6**. The 46 existing project/runtime/dev lock versions
remain unchanged; [runtime evidence](runtime-evidence.json) lists every installed distribution.

Isolated build: hatchling **1.32.4**, packaging **26.3**, pathspec **1.1.1**, pluggy **1.7.0**,
tomlkit **0.15.2**, trove-classifiers **2026.9.21.13**, with [six archive hashes](build-toolchain.json).
They do not become application runtime dependencies.

Node **24.22.1**, npm **11.19.1**, React/React DOM **19.3.1**, TypeScript **7.0.2**,
Vite **8.3.5**, Playwright **1.64.1**, Chromium **156.0.8078.4** (revision 1248).
React type packages **19.3.0**, Node types **26.6.5**. Exact lock/build hashes are in
[frontend evidence](frontend-evidence.json).

Semgrep **1.179.0**, Trivy **0.76.1**; image, executable, rule and vulnerability-DB hashes
are in [scanner evidence](scanner-regression.json) and [the registry](../../policies/scanners.lock.json).
The public offline DB is **1,627,238,400 bytes** and was verified against its retained hash.
No scanner policy/image/database refresh was performed. Dockerfile/Compose retain pinned
base-image digests; the clean application image ID and source hashes are in
[rebuild evidence](rebuild-evidence.json).

## Executed validation

| Group | Passed | Failed | Skipped/blocked |
| --- | --- | --- | --- |
| Complete backend/API/PostgreSQL/process/evaluation suite | 286 | 0 | 0 |
| Native lifecycle/reporting subset | 53 | 0 | 0 |
| Native NTFS boundary | 10 | 0 | 0 |
| Actual scanner containment | 31 | 0 | 0 |
| Genuine scanner detection/failure/poisoning regression | 16 | 0 | 0 |
| Full Chromium suite | 19 | 0 | 0 |
| Clean-context compiled preview | 1 | 0 | 0 |
| Initial matched restore / corruption / interruption | 17 | 0 | 0 |
| Latest backup / fresh instance / operator CLI replay | 7 | 0 | 0 |
| Retention / quota / clean workers | 9 | 0 | 0 |
| Uncached build / matching web artifacts | 4 | 0 | 0 |
| Clean/restored APIs, restrictions, ACL and shutdown | 13 | 0 | 0 |
| Controlled genuine end-to-end demonstration | 8 | 0 | 0 |
| Clean CI artifact fallback | 7 | 0 | 0 |
| Supply-chain review | 9 | 0 | 0 |
| Frontend confidentiality/build/auth/log checks | 10 | 0 | 0 |
| Development runtime / retained-row preservation | 34 | 0 | 0 |
| Frozen outcomes / historical evidence / Git boundaries | 10 | 0 | 0 |

Counts overlap. The full suite includes **25 scan crash/retry** and **five triage recovery**
experiments with real PostgreSQL and separate processes. The browser suite separates
11 actual persisted workflows, three security contracts and five scripted scenarios.
Clean CI additionally ran **176 unit/API tests** without network; PostgreSQL cases were
executed in the full suite. Remote Actions and code-scanning upload were not run.
Ruff, mypy (67 files), strict TypeScript, frozen installs and builds pass.

See [exact commands](COMMANDS.md), [validation and performance](VALIDATION.md),
[machine acceptance](acceptance.json) and the linked case-by-case JSON artifacts.
Initial failures/corrections are disclosed; no safeguard or frozen label was weakened.

## Retention, backup and restore evidence

The [recovery contract](RETENTION-AND-RECOVERY.md) details private ownership, seven-day orphan
eligibility, publisher/DB locks, bounded dumps, trusted manifest digests and exact disposable
targets. Two private matched bundles were created and retained. No operator credential
configuration or image archive was included; raw source inside them remains confidential.

The first restore matched **18 table fingerprints / 13 registered sources**. Corrupted,
missing and mismatched payloads were rejected before database mutation. A real pg_restore
backend was killed at controlled transactional DDL, rolled back all application tables
and retried successfully. Missing restored source produced explicit abstention and a
409 export refusal while successful scanner records stayed unchanged.

The latest backup includes completed demo/browser history and restored into a separate
fresh instance with **18 matching table fingerprints / 14 registered sources**. Actual API
queries preserved project/scan/finding/triage/review relationships and produced the same
source-verified genuine report as development. Operator CLI replay verified the matching
target without replacement. Earlier restore/data destinations were not overwritten.

The production retained spool was inspected only: **15 publications, 14 registered,
59,939 bytes**, zero removed. Seven local exports use **364,231 bytes**, zero removed.
Two private backup bundles total **1,385,894 bytes** at final inspection. Quotas remain
32/128 MiB source, 64/64 MiB reports, three/384 MiB-per-bundle backups. One eligible orphan
was reclaimed only in the explicitly disposable clean-spool test; all referenced source
and DB rows survived. [Storage evidence](storage-evidence.json).

## Existing-data preservation and evaluation

Every pre-existing row remains unchanged by fingerprint comparison across 17 application
tables. Development now has 15 projects, 14 registered sources, 30 scans, 1,911 findings,
28 triage outcomes, seven reviews and 39 immutable revisions. Phase 7 intentionally added
two controlled projects, one source, two scans, 86 genuine findings, six offline triage
runs, two new reviews and nine revisions. Original mutable review rows/history were untouched.

Frozen quality/category/support and adversarial outcomes match Phase 6. Timing observations
vary; the final run has three one-byte context/token differences across unsupported
dependency and ungraded Kubernetes cases, investigated under the existing stable comparison. Labels, rules, prompts and agent behavior
were not changed. A13 unsupported advisory semantics, two ungraded Kubernetes bindings,
unsupported/incomplete scanner cases and limited deterministic coverage remain visible.

The fixed 1/2/4-worker workload and EXPLAIN plans were rerun. Actual local query p50/p95:
findings **2.483/3.794 ms**, history **1.360/1.942 ms**, n=30 each. These ORM/database
observations are not HTTP latency, improvements or production SLOs. Six diagnostic runs
cover 72 scans / 144 jobs / 15,120 synthetic findings; detailed timings/resources and
shared-host/cache limitations are in [VALIDATION.md](VALIDATION.md). No new index was added.

## Demonstration, limits and safe operation

[DEMONSTRATION.md](DEMONSTRATION.md) shows the controlled genuine scan, explicit offline
investigation/abstention, human revision/conflict, JSON/SARIF/policy and restart recovery.
[PORTFOLIO.md](PORTFOLIO.md) supplies factual résumé/interview statements with denominators.

Remaining limits include trusted local host/browser/DB administration, Chromium-only and
focused accessibility validation, imperfect secret heuristics, conservative history
retention, private unsigned/unencrypted-by-application backups, finite maintenance quotas,
separately retained scanner assets and no live hosted-model quality result. DB history
itself is retained rather than automatically purged. A full quota requires operator review.
Full details are in the [threat model](THREAT-MODEL.md) and finding register.

Development API/workers and UI remain available, with real/hosted admission disabled.
The dedicated test/clean/initial-restore/latest-restore services are stopped, with volumes,
spools, failed-drill artifacts and both backups preserved. No scanner/CI orphan remains.
Use [RUNBOOK.md](RUNBOOK.md) for startup/shutdown/restart and rollback. Keep compatible
revision-0004 code/data; do not downgrade retained data or restore over development.

Earlier Phase 7 review evidence is preserved in `review-1/`; final root reports validate
the completed sandbox-capability fix. There is no architecture or scope expansion. No staging, commit, push, public deployment,
remote workflow activation, hosted call, Phase 8 implementation or Matroid change occurred.
Stop at Phase 7. Any optional extension or separate audit needs its own authorization.
