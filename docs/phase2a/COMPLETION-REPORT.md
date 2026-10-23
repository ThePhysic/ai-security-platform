# Phase 2A completion report

Phase 2A only: the authenticated AppSec foundation now supports immutable local intake,
transactional acceptance and durable synthetic workers. Brain Co secure-workflow and
Prophet backend overlap remains secondary. No Phase 2B scanner/launcher, AI, review,
export, frontend, SOC or Matroid implementation was performed.

Both implementation checkpoints passed local validation; G2 and G3 pass. See
[runbook](RUNBOOK.md), [implemented contracts](API-AND-SCHEMA.md),
[file inventory](FILES.md) and [executed commands](COMMANDS.md).

## Architecture and retained data

The native CLI privately publishes validated independent bytes to a Windows-owned
spool using canonical manifests, hashes, provenance, quotas, pinned handles and atomic
rename. API and worker consume its actual Docker Desktop read-only bind at /spool.
Server verification is mandatory; no writable consumer/platform fallback exists.
No target code, dependency installer, script, shell, repository policy or remote URL
is executed. Source acquisition on unsupported filesystems fails closed.

Revision 0002_orchestration extends 0001_foundation with scanner_runs, jobs,
job_attempts, findings, idempotency_requests, snapshot verification/admission timestamps,
constraints/indexes and expanded allowlisted audit events. Existing development data
was backed up before forward migration; counts stayed 3 projects, 0 snapshots, 0 scans
and 3 audit events. Later controlled validation records were intentionally retained.
[Migration evidence](migration-evidence.json) records the private ignored backup.
No retained database was downgraded, reset or reconstructed.

Acceptance commits parent, two independent scanner slots/jobs, idempotency record and
audit together. Replay resolves before current eligibility/capacity checks; conflicting
semantic requests return 409. Worker processes claim with SKIP LOCKED and fresh DB time,
unique tokens, increasing generations, independent heartbeats, hard deadlines, bounded
retry/backoff and explicit expiration recovery. Completion/failure/recovery consistently
lock job -> scanner -> parent. Findings, state, attempt history and audit commit under
the ownership fence in the same transaction. This is at-least-once compute with fenced
publication, not exactly-once execution.

Only versioned fake-patterns/fake-config adapters exist. Every finding/coverage response
identifies synthetic evidence; messages never contain source excerpts. Successful
scanner results survive a peer's terminal failure. Bounded signed cursor reads expose
history and findings without OFFSET. Existing auth, Host/Origin rules, request limits,
error sanitization, synchronous handlers and structured logging remain.

## Validation and checkpoints

| Checkpoint/gate | Status | Evidence |
|---|---|---|
| 2A-I: secure intake and durable acceptance | PASS | Native filesystem and live mount proof; registration, transactional/idempotent acceptance and retained migration tests |
| 2A-II: execution and recovery | PASS | Separate processes, independent heartbeat, expiry/generation/token fencing, retries/partial results and recovery |
| G2: durable orchestration | PASS | Real PostgreSQL claims/completions, all 25 crash trials, stale publication rejection and DB outage recovery |
| G3: snapshot and resource boundaries | PASS | Windows/POSIX protections, digests/provenance, read-only transport, mutation/budget/cleanup and bounded query checks |

Final Linux container suite: **144 passed, 0 failed, 0 skipped**, including 25 crash
experiments. Native Windows unit/API run: **79 passed, 0 failed, 0 skipped**.
Administrator-run native filesystem harness: **10 passed, 0 failed, 0 blocked,
0 skipped**. Live service/boundary checks: **8 passed, 0 failed, 0 skipped**.
These are separate runs with overlapping coverage, not additive unique-test counts.
Native marker deselection excludes PostgreSQL tests subsequently executed in containers.
Native/container Ruff and mypy passed; mypy checks 43 source files. Frozen lock/sync
passed with 41 locked packages. One upstream HTTPX/Starlette warning remains.

Python 3.12.15, uv 0.13.5, PostgreSQL 17.11; FastAPI 0.161.0, Pydantic 2.14.1,
SQLAlchemy 2.0.55, Alembic 1.20.1 and Psycopg 3.3.6. All dependency versions are
recorded in runtime-evidence.json and uv.lock. Migration: 0002_orchestration.

Evidence files:

- [Container checks and 25 individual crash trials](test-evidence.json).
- [Native Windows filesystem checks](windows-filesystem-evidence.json).
- [Actual CLI/mount/service restart evidence](live-evidence.json).
- [Versions and final environment checks](runtime-evidence.json).

The native harness initially exited nonzero: Windows denied symlink creation with
WinError 1314. The operator then ran the requested harness in an administrator shell;
its generated evidence records 10 passed, zero failed/blocked/skipped, including file
and directory symlinks, junction root/child, hardlink, ADS, writer denial and traversal.
This administrator-run artifact is distinct from our ordinary native test execution.

Crash distribution is five independent trials each after claim, after output, after
finding insertion before commit, after commit before acknowledgment, and after a real
PostgreSQL backend termination during publication. Each trial uses a separately spawned
process and actual database transactions; it verifies expected findings, exactly one
completion event and stale-publication/heartbeat rejection. Pre-commit failures recover
at generation 2; post-commit loss stays generation 1 without republishing. The primary
crashed slot is deliberately the adapter that inserts a finding.

Additional real-PostgreSQL tests exercise four competing claiming processes, simultaneous
scanner completions, token/generation/expiry/deadline checks, same-key and different-key
stale result rejection, fail/audit rejection, independent heartbeat through slow work,
retry exhaustion, partial results, rollback after insertion, concurrent same/conflicting
submissions and response-loss replay. Nonempty finding/history pagination checks bind
filters, prevent duplicate traversal and verify bounded LIMIT/no OFFSET statements.

Live checks use the native installed CLI, retained development database and separate
API/worker containers. Queued work survives actual API/DB restarts before any worker
starts; findings and outcomes survive subsequent API/worker/DB restarts. The same
worker recovers after a real database stop/start. Actual write syscalls into /spool fail
in both consumers. Inspection verifies non-root, read-only mounts/root, dropped
capabilities, no-new-privileges, CPU/memory/PID bounds, no privileged mode/socket,
internal DB and worker networking, and loopback-only API publication. Auth, Host/Origin
denials and synthetic-secret absence from responses/logs are checked.

Initial static checks caught platform-specific ctypes/msvcrt typing errors on Linux;
casts preserve native behavior and the Linux/Windows type checks were rerun.
The existing upstream HTTPX/Starlette test-client deprecation remains visible.
No required integration test is silently skipped or replaced by mocks.

## Limits, deviations and remaining risks

There is no stack or role-priority change and no added external infrastructure or
runtime dependency. Existing uv.lock remains valid; CLI entry point metadata changed.
Namespace names remain asp-phase1-dev/test to preserve the established volumes.

- Published source is conservatively retained; admission expires after 24 hours and
  quotas stop new intake, but there is no automatic published-source TTL deletion.
  Only abandoned unpublished staging is cleaned. This explicit retention limitation
  protects all current/history references; a hard data deletion obligation is unsupported.
  Reference-aware reclamation and paired restore remain later hardening work.
- Windows acquisition intentionally rejects non-NTFS/network volumes, Unicode/space
  filenames, links and busy files. This reduces compatibility in favor of fail-closed
  behavior. Revalidate after Docker Desktop/filesystem changes.
- The trusted local operator, administrators, Docker Desktop and DB writers remain
  privileged. Read-only mounts/ACLs do not prevent their deliberate modification;
  application fencing/audits are not DB-administrator tamper resistance.
- Copy validation detects observed mutation and pins Windows writers; it does not
  prove a globally atomic working-tree revision or complete secret exclusion.
- Fake adapters establish orchestration only. No real vulnerability accuracy, arbitrary
  code sandboxing, egress isolation, production SLO, large-scale throughput or real
  scanner containment claim is supported. G4/G5 remain open.
- Linux CI is defined locally with read-only permissions and guarded disposable data.
  It was not remotely activated and cannot replace native Windows validation.

These limits are visible in the runbook/API coverage; none is hidden behind fake
successful scans. No commits, staging, pushes, deployment or external provisioning occurred.
Local instructions stayed ignored and unmodified.

The complete inventory contains 18 modified and 38 created project files. Module
groups implement intake/CLI, scanner contracts/fakes, durable jobs, schema/API extension,
security-preserving configuration, tests, local validation tooling and operational
documentation. No application areas belonging to later phases were introduced.

## Safe operation and next handoff

Use the [runbook stop/restart/rollback procedures](RUNBOOK.md#stop-restart-and-rollback).
Stop this project's API/worker to contain intake/claims; preserve DB, source and attempts.
On restart, expiration recovery reconciles old ownership. Do not erase stuck jobs.
No destructive retained downgrade is supported; use a compatible forward correction.
The old Phase 1 image expects 0001 and is not a ready rollback for 0002. Restore only
an approved matching DB/spool pair, never automatically over retained data.

**Recommended Phase 2B handoff — NOT AUTHORIZED:** begin with the separate trusted
host-side fixed-profile launcher and actual Windows/Docker Desktop isolation tests.
API, ordinary workers and scanner containers must never acquire daemon authority.
Keep fake-v1 as the diagnostic path; then add Semgrep/Trivy adapters and trusted
policies/provenance/bounded normalization with partial outcomes. If G4 cannot be
proved, enforce approved controlled-fixture mode and report the untrusted-isolation
gate open. Revisit raw retention/reclamation policy before expanding sensitive intake.
Do not begin any of this without separate authorization.
