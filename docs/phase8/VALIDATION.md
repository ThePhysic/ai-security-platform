# Phase 8 validation

Local Windows/NTFS, Docker Desktop Linux containers and real PostgreSQL; no live enterprise
events, hosted model calls, remote workflow activation or source transmission.

| Validation | Passed | Failed | Skipped / blocked |
| --- | --- | --- | --- |
| Complete applicable backend/API/PostgreSQL/process/evaluation suite | 319 | 0 | 0 |
| Final affected unit/API/SOC PostgreSQL suite | 209 | 0 | 0 |
| Actual scanner containment | 31 | 0 | 0 |
| Genuine scanner detection/poisoning/failure regressions | 16 | 0 | 0 |
| Native Windows filesystem checks | 10 | 0 | 0 |
| Selected Chromium regressions | 15 | 0 | 0 |
| Actual isolated CLI/API/worker demonstration | 9 | 0 | 0 |
| Fresh allowlisted build and matching dashboard assets | 4 | 0 | 0 |
| Retained data, capabilities, confidentiality and frozen baselines | 17 | 0 | 0 |
| Optional overlay configuration and disabled-worker refusal | 3 | 0 | 0 |

Counts overlap; do not add them into a unique-test total. The 33 new SOC tests consist of
19 unit/security cases and 14 real PostgreSQL cases. The complete 319 includes the prior
286 tests, **25 scan crash/retry experiments** and **five triage recovery experiments**.
The final 209 reruns unit/API tests and all SOC PostgreSQL tests after strengthening the
nonempty AppSec removal assertions. Ruff and strict mypy pass (80 source files).
Strict TypeScript and locked npm builds pass. No new dependency or lockfile change.

## SOC functional and security evidence

- Four independently labelled synthetic scenarios: two matched, one clean under these
  predicates and one explicitly incomplete. CLI replay returns the same accepted run.
- PostgreSQL multiprocess ingestion races preserve one canonical request; conflicting
  semantics return 409. Four independent claimants produce only one live lease.
- Two reviewers racing revision zero yield exactly one success and one 409. Notes are
  redacted, revisions/audits persist, and history/event/audit mutations are rejected.
- Killing a separate process during publication rolls its transaction back. The expired
  lease recovers at the next generation; stale heartbeat/result/failure/audit publication
  is rejected. Killing after commit leaves one authoritative completion and no reclaim.
- Terminating the database connection during result publication rolls back investigations and
  completion audit together. Retrying publication under still-valid ownership succeeds.
- Bounded retries reach visible terminal failure. Invalid result evidence is rejected by
  recomputation. Late authentication produces a new matched occurrence while preserving
  the earlier incomplete timeline and its stable anchor tracking ID.
- Signed keyset cursors cannot cross dataset/endpoint filters. Timeline reads verify exact
  event identities, hashes and timestamps; four-event linked evidence is checked through
  the API. Unsupported payloads/URLs/credentials/paths/extra fields and oversize inputs
  fail validation; synthetic notes and malformed requests do not disclose their test secret.
- Fresh/repeated optional migration, schema-only autogeneration, disposable downgrade and
  re-upgrade pass. Public table fingerprints, including a real AppSec project/audit,
  survive schema removal. A separate process runs a physical package copy **without SOC**,
  queries a persisted AppSec project and verifies readiness and absent optional routes.
- Enabled SOC with unavailable schema returns 503 without making public readiness fail.
  Disabled routes return 404. The standalone disabled worker claims nothing.

[SOC PostgreSQL evidence](soc-postgres-evidence.json), [complete results](test-evidence.json)
and [final affected suite](final-focused-evidence.json) preserve the commands and outcomes.
The test sources identify individual assertions; recovery markers expose only synthetic
checkpoint facts, not database credentials or raw event/source contents.

## Real environment and historical queries

The isolated `asp-phase8-demo` namespace has PostgreSQL, API and a separate SOC worker.
Four real CLI/API submissions persist **8 events, 4 runs, 3 investigations and 1 analyst
revision**. Actual database/API/worker restart preserves those records and successful
run identities. Disabling the API module removes routes without altering counts; AppSec
readiness remains healthy. Services are stopped and the private volume/config retained.
Containers enforce non-root consumers, read-only filesystems, capability drop, no-new-
privileges and bounded resources. No source/Docker bind or launcher/provider credential
is supplied to the SOC worker. [Environment evidence](environment-evidence.json).

The controlled history workload contains 1,000 events in one dataset, ingested through
50 bounded batches. `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` uses
`ix_soc_events_history` with an Index Only Scan under LIMIT 20. Observed planning/execution
time was **0.314 / 0.054 ms**, one local plan observation with warm hits and heap fetches.
This is neither HTTP latency nor a throughput/SLO claim. No forced planner setting or
speculative AppSec index was added. The 1,001st event is rejected without changing count.

The original fixed AppSec diagnostic workload also reran: 1/2/4 workers, 72 scans,
144 jobs and 15,120 synthetic diagnostic findings across six runs. Query observations,
n=30: findings p50/p95 **2.836/4.448 ms**, history **1.761/3.081 ms**. One findings sample
was 139.187 ms; no improvement claim is made. Shared Windows/WSL/Docker host activity,
retained caches and concurrent local validation prevent production-capacity interpretation.
[Complete measurements and plans](performance-evidence.json).

## Prior guarantees and reproducibility

Actual scanner probes reran (31 isolation/16 detection), independently of the frozen
112-container Phase 4 observations used for offline benchmark replay. The full corpus
and two adversarial repetitions preserve quality/category/evidence-support outcomes.
Timing/context usage can vary as previously documented; labels and policy bytes remain
unchanged. A13 still accepts unsupported advisory remediation without action authority;
two Kubernetes bindings remain ungraded. There is no new SOC/AI discovery claim.

Chromium's 15 selected cases comprise seven live persisted read-only/denied-operation
workflows, three browser security contracts and five explicitly scripted transport cases.
They cover memory-only authentication, denied origins/hosts/hosted requests, safe hostile
content, incomplete scan display, source/finding navigation, keyboard/mobile workflow,
bounded responses and page-scoped metrics. Existing review-write/triage browser scenarios
were not repeated against retained records; their backend regressions ran with PostgreSQL.
No SOC dashboard was added. [Browser evidence](browser-evidence.json).

Fresh context/no-cache runtime build and frozen npm build succeeded; compiled dashboard
asset hashes match the ordinary locked build. No private state/instructions were packaged.
[Build evidence](rebuild-evidence.json). Earlier full backup/restore and supply-chain
network audit evidence remains accepted and unchanged; those independent Phase 7 drills
were not all rerun because Phase 8 changes no public schema, source storage, backup code,
scanner artifacts or dependencies. This is an explicit relevance boundary, not a skipped
mandatory SOC check. SOC volume persistence is not a new backup/restore assurance.

[State evidence](state-evidence.json) verifies all 18 retained public/version-table
fingerprints, disabled admission, unchanged locks/frozen data/prior reports, private
instructions and absence of actual local credentials in published evidence, browser
assets and backend logs. Retained development was not SOC-migrated. Final scanner/model
admission remains disabled. No unrelated service was modified.

## Failures corrected and scope limits

The first focused run had one harness failure: a read left an active SQLAlchemy
transaction before invoking transaction-owning replay code. The harness now closes that
read transaction. The first full run hit pytest's duplicate `test_soc` import name; the
unit file was renamed. Both were corrected and rerun. Native symlink creation initially
required elevated Windows privileges; the operator's separate report was verified at
10 passed, zero blocked. The initial retained-data probe found the project's DB stopped;
it was started before recording the first successful baseline, with no data mutation.
The first host lock check could not access uv's global cache under the sandbox; the
offline check passed using the project-owned `.cache/phase8-uv` cache instead.

There are no unresolved required Phase 8 failures or blocked checks. Finite tests do not
prove universal security. The [threat model](THREAT-MODEL.md) and [runbook](RUNBOOK.md)
describe single-operator trust, conservative quota/retention, non-MVCC history traversal,
synthetic-only input, advisory correlations and unvalidated SOC backup recovery.
