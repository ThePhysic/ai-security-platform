# Acceptance Tests, Evaluation and Reliability

Status: **Planned evidence only; no implementation checks run in Phase 0.** Module owners below are code responsibility boundaries, not authorization for delegation or parallel agents. [05](05-PHASES-AND-ACCEPTANCE.md) owns phase gates; [09](09-PHASE1-SPECIFICATION.md) details foundation checks.

## Traceable acceptance tests

| ID | Owner | Required evidence | First gate |
|---|---|---|---|
| T-FOUNDATION | `api/`, `storage/` | Locked environment, fresh/head migration, disposable downgrade/re-upgrade, DB/schema readiness, persisted records across restart | G1/1 |
| T-ACCESS | `api/` | Missing/wrong token denied; allowed token succeeds; disallowed/null Origin and Host rejected; no broad CORS; no public DB port | G1/1, G9/6 |
| T-API | `api/`, `domain/` | Typed contracts, sanitized errors/OpenAPI, limits, absence of unimplemented routes; later 202/409/cursors | G1/1, G2/2A |
| T-LOG | `api/` | Synthetic bearer/DSN/body values absent from success/error/validation/access logs; bounded safe request IDs | G1/1 |
| T-QUEUE | `jobs/`, `storage/` | Atomic acceptance, duplicate/mismatch response, racing claim, generation/token fence, heartbeat expiry, retry exhaustion | G2/2A |
| T-CRASH | `jobs/`, `storage/` | Worker kill/DB outage/finalization rollback; 25 controlled trials; no stale findings/states/audit publication | G2/2A, G8/5 |
| T-SNAPSHOT | `snapshots/` | Traversal/link/junction/stream/special-file/collision/mutation rejection; manifest verification, scope/provenance, safe publication and cleanup | G3/2A |
| T-LIMITS | Intake, runner, query owners | Input/body/queue/disk/output/finding/CPU/memory/PID/runtime/cursor bounds; controlled visible failure | G3/2A, G4/2B, G8/5, G10/7 |
| T-ISOLATION | `runner/` | Actual Windows/Docker Desktop restrictions, denied egress/mount writes/privileges/daemon access, no source execution | G4/2B |
| T-LAUNCHER | `runner/` | Fixed profile interface, separate credential, no arbitrary argv/mount/image; stale invocation/result rejected; orphan cleanup | G4/2B |
| T-POLICY | `scanners/`, `policies/` | Poisoned config/ignores/inline suppression/environment cannot weaken audit mode; immutable rule/DB provenance | G5/2B |
| T-ADAPTER | `scanners/` | Positive/clean fixtures, severity mapping, occurrence identity, malformed/deep/oversized output, unsafe result paths and missing DB | G5/2B |
| T-DISCLOSURE | Scanner, agent, reporting owners | Synthetic secrets absent from persisted findings, traces, hosted requests, errors, JSON, SARIF and UI; raw-source boundary explicit | G5/2B, G6/3, G8/5, G9/6 |
| T-AGENT | `agent/` | Necessary finding/source retrieval, scoped reads, bounded loop, validated citations, abstention, injection resistance, consent and provider failure | G6/3, G7/4 |
| T-REVIEW | Review storage/API | Expected revision 0 initialization, concurrent update 409, atomic current/revision/audit, reviewer spoof rejection | G6/3 |
| T-EVAL | `evaluation/` | 20 labelled fixtures, 10 adversarial cases, held-out results, baseline comparison and supported metrics | G7/4 |
| T-CI | CLI/workflow owners | Clean-checkout workflow, no target scripts/fork secrets/privileged checkout, least privilege, safe artifacts | G8/5 |
| T-SARIF | `reporting/` | Schema validation, canonical source locations, deterministic safe output, coverage and valid tool metadata | G8/5 |
| T-LOAD | Query/jobs owners | Fixed workload, p50/p95/throughput/queue wait/retries and EXPLAIN; correctness under concurrent load | G8/5 |
| T-UI | `web/` | Persisted states/metrics, accessibility, errors/conflicts, safe rendering and authenticated browser requests | G9/6 |
| T-RESTORE | Storage/snapshot owners | Matching DB/spool restore, missing evidence handled, active refs protected, clean rebuild and retention | G10/7 |

For platform-specific cases that cannot run on a developer machine, run the required supported-environment job and report it. Do not count skipped Windows junction or PostgreSQL locking tests as evidence. Restricted-fixture fallback has its own rejection tests and does not pass T-ISOLATION.

## Queue/failure experiment matrix

Use a deterministic fake scanner with expected result sets and synchronization barriers, not timing-only sleeps. Execute separate processes against real PostgreSQL, never SQLite. Record generation, phase of kill, recovery interval, expected/actual rows and audit state.

1. Concurrent same key/same semantic body; same key/different body; different keys. Lose response after acceptance commit and replay. Replay after capacity is full, profile defaults change or source retention expires must still return the original accepted resource.
2. Two/four workers race one eligible job. No overlapping valid lease; later duplicate compute remains possible after expiry.
3. Kill before invocation, during fake execution, after output but before publication, and during transaction before commit.
4. Kill after commit but before worker observes success. Retry/recovery must not republish or duplicate findings.
5. Old worker resumes after reassignment: reject stale heartbeat, same-key findings, different-key findings, scanner/scan/triage states and audit writes.
6. Expired lease before reassignment is already invalid. A healthy independent heartbeat preserves current ownership; hard deadline still terminates a hung attempt.
7. DB unavailable during claim, heartbeat and completion; rollback partial writes; recovery/retry or visible terminal state after exhaustion.
8. Concurrent scanner completion serializes aggregate status correctly; one scanner succeeds while the other fails, retries or has incomplete coverage.
9. Scanner crashes, times out, emits invalid/deep/non-JSON/oversized output; Trivy DB absent/stale; policy supply unavailable.
10. Launcher dies and restarts; reconcile orphaned attempts without attaching them to replacement leases or deleting unrelated containers.
11. Hosted provider timeout/rate limit/invalid structure/injection; no scan rollback or automatic permission expansion. Potential duplicate billing is disclosed.
12. Concurrent review writers; stale revision conflicts and no silent lost revision/audit.

At least 25 controlled crash/retry trials are required in Phase 2A, distributed across the critical fake-execution/commit/lease/DB failure cases above. Report distribution, not only a total. Later phases add real-runner/provider cases. These trials demonstrate observed invariants, not a mathematical proof or production failure rate.

## Fixture and evaluation design

At least 20 source-only labelled repository fixtures: Python and TypeScript where supported; SQL/injection patterns, authorization, deserialization, paths, synthetic secrets, vulnerable/patched dependencies and selected Dockerfile/CI configurations, with clean/near-miss counterparts. No target fixture scripts are executed. Test scanners with pinned engines/rules/DBs and record exact coverage.

Label actual security behavior separately from expected scanner detectability. Authorization flaws may require manual reasoning; disclose unsupported categories. Include scanner false positives, shifted lines, changed scope, malicious comments/filenames/output and mismatched context.

Separate tuning/development cases from held-out evaluation. Record label rationale, corpus version, policy/DB/model/prompt/tool versions and seeds where applicable. Phase 3 contains initial adversarial tests; Phase 4 expands to at least 10 adversarial cases with distinct attack goals.

Report precision/recall/confusion matrix only where labels and denominators support them. Triage metrics: correct/incorrect/abstain, evidence-supported recommendation rate, unsupported claims/remediation, reviewer correction, token/cost/time when measured. Do not claim triage improves discovery recall without independently labelled discovered issues. Avoid treating at-least-once retry outputs as independent samples.

Safety metrics: attempts blocked, observed successful unauthorized actions (target zero), cross-snapshot access and synthetic disclosures (target zero). Zero observed violations is limited to the test corpus. Hosted runs are separately reported and can vary; deterministic provider is a reproducible test harness, not production accuracy evidence.

## Workload and operational measurement

Start with a fixed representative snapshot of about 100–300 small source/config files. Record hardware, OS/Docker versions, scanner/profile/DB digests, dataset, concurrency and cold/warm caches. Measure queue wait, scanner/runtime, end-to-end latency, p50/p95, throughput, retry/error rates and DB query plans. Use 1/2/4 workers where hardware permits; record unsupported runs rather than implying they passed.

Set regression budgets from observed controlled baselines, not invented wall-clock SLOs. Correctness and bounded resource use precede throughput. Structured logs and persisted timing fields are sufficient initially; do not add a metrics platform as an unstated dependency.

## Future verification commands

These are commands to implement/document in their assigned phases, not commands executed or installation permission granted in Phase 0:

```text
uv sync --frozen
uv run ruff check .
uv run mypy src
uv run pytest -m unit
uv run pytest -m api
uv run pytest -m postgres
uv run pytest -m orchestration
uv run pytest -m scanner
uv run pytest -m agent
uv run pytest -m evaluation
uv run pytest -m reliability
```

Register markers when introduced. Phase 1 uses unit/api/postgres only; future markers must not create empty mandatory runs. Required environment absence is a failing/blocked gate, not silently skipped green CI. Each phase records exact commands, counts and outputs. Test DB and spool must be explicitly identified disposable resources; never connect cleanup/downgrade tests to ordinary developer data.

Phase 1 migration/Compose commands and execution prerequisites are in [09](09-PHASE1-SPECIFICATION.md). Later scanner, CLI, evaluation and web commands must be concrete when their actual entry points exist. Never invent successful checks or claim code/services were exercised during planning.

## Release evidence

Use measured scope, accuracy, latency and recovery claims only. Do not claim production scale, real customers, complete detection, zero vulnerabilities, tamper-proof audits, arbitrary-code sandboxing or perfect secret redaction. All benchmark and demo reports identify restricted-fixture mode if G4 is still open.
