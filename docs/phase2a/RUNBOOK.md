# Phase 2A local runbook

Secure local source intake and durable **synthetic** scanning extend Phase 1.
The only profile is `fake-v1`; marker matches are test findings, not vulnerability detections.
Phase 2B requires separate authorization. Historical Phase 1 evidence stays in `docs/phase1/`.

## Setup and start

Use the existing Python 3.12/uv environment, Docker Desktop Linux engine and ignored
credentials. Never replace existing database credentials or print resolved Compose configuration.
Run in the repository root:

~~~powershell
uv sync --frozen
uv run python scripts/bootstrap_local.py
uv run asp spool-init
docker version
docker compose -p asp-phase1-dev --profile workers config --quiet
docker compose -p asp-phase1-dev --profile workers build api worker
docker compose -p asp-phase1-dev up -d --wait db
docker compose -p asp-phase1-dev run --rm api uv run --no-sync alembic upgrade head
docker compose -p asp-phase1-dev --profile workers up -d --wait api worker
~~~

For an existing Phase 1 database, `uv run python scripts/phase2a_migrate.py`
is the alternative that verifies fixed database/project identities, stops the API,
takes a private custom-format backup, builds/migrates forward and compares retained
table counts. Run it with no other writers. Its ignored backup is not a restore drill.
The completed migration is recorded in `migration-evidence.json`.

Initialize the spool before creating containers: mounts have `create_host_path: false`.
The Windows writer uses the native workspace path; Linux consumers use `/spool`.
These identify one mount, not interchangeable path strings. The private spool grants
the current Windows user and SYSTEM access. A filesystem/Docker Desktop configuration
change requires rerunning the native and live boundary proofs. Never relax ACLs or
enable writable consumer fallback.

API publishes on `127.0.0.1:18081` only. PostgreSQL and worker have no published ports.
API/worker use UID/GID 10001, read-only roots and spool, dropped capabilities,
no-new-privileges, 256 MiB memory, one CPU and 64 processes. No Docker socket is mounted.
The explicit workers profile starts execution; API alone durably queues work.

## Minimal local workflow

~~~powershell
uv run asp project-create "Controlled fixture"
uv run asp snapshot-create C:\path\to\authorized-fixture --label controlled-fixture
uv run asp snapshot-register --project PROJECT_UUID --key SNAPSHOT_KEY --digest MANIFEST_SHA256
uv run asp scan-submit --project PROJECT_UUID --snapshot SNAPSHOT_UUID --idempotency-key unique-operation-key
uv run asp scan-status SCAN_UUID
uv run asp scan-history --project PROJECT_UUID --limit 50
uv run asp findings SCAN_UUID
~~~

Replace uppercase placeholders with returned identifiers. The CLI reads its bearer
from ignored `.env` or `ASP_API_TOKEN` without printing it. An explicit
`--api http://127.0.0.1:PORT` precedes the command. Redirects and environment proxies
are disabled. Exit 2 denotes an invalid/failed operation. Phase 5 wait/export/policy
exit contracts are not implemented.

`ASP_FAKE_FINDING` produces synthetic pattern findings; `ASP_FAKE_CONFIG` produces
synthetic config findings. Source is never executed, imported or installed. Descriptions
are constants with no excerpts. The markers prove transport/normalization/persistence,
not security detection. Missing/altered snapshots and oversized results visibly fail;
successful scanner results survive peer failure.

## Snapshot boundaries, quotas and retention

Trusted exclusions live in `snapshots/policy.py`. Repository instructions, ignore files
and scanner configuration are data. Local instruction files, `.env` except `.env.example`,
common private key files and VCS/credential/dependency/build/cache directories are
excluded. This filename policy is not a complete secret detector.

Windows acquisition supports local fixed NTFS only. Intake rejects links, reparse
points/junctions, hardlinked files, alternate streams, special files, ambiguous/colliding
names, unsafe paths and observed mutation. Windows pinned handles deny write/delete
sharing; POSIX uses directory-relative no-follow handles and nonblocking file opens.
Bytes/listings are checked again before publication. This is a validated copy, not
proof of a repository-wide atomic checkout.

Defaults: 512 files; 128 directories including the traversed root; 2,048 enumerated
entries including exclusions; depth 16; path 240 ASCII bytes; component 120 characters;
1 MiB/file; 16 MiB content; 256 KiB manifest; 32 published snapshots; 128 MiB spool.
Unicode, spaces, stream separators and Windows device names are deliberately rejected.
No archives or clones. An exclusive writer lock serializes staging and atomic rename.
No key is overwritten. Server verification checks canonical JSON, policy/content hashes,
paths, sizes and the complete manifest against the actual read-only mount.

New admission expires 24 hours after acquisition by default (configurable within
60 seconds to seven days). Replays resolve their original resource after expiry;
accepted jobs may finish against retained verified bytes. Old Phase 1 metadata stays
unverified and cannot be submitted as acquired source.

Published raw source is retained until approved reference-aware reclamation exists.
Phase 2A does **not** implement automatic TTL deletion: expiry limits new use, disk/count
quotas bound storage, and a full spool stops intake. This protects active/history
references but does not meet a hard deletion deadline. Do not ingest data requiring one.
Full retention/restore automation remains a later hardening task.

~~~powershell
uv run asp snapshot-cleanup-staging
~~~

Cleanup removes only validated platform-owned unpublished staging older than one hour,
under the publisher lock. It never removes published snapshots or DB rows.
Do not manually prune references or remove spool/DB volumes. The operator,
administrators and Docker Desktop remain trusted; consumer mounts do not constrain
a compromised host administrator or the same privileged local user.

## Execution and diagnostics

Acceptance records the parent, two scanner slots, two jobs, idempotency identity and
initial audit event in one transaction before 202. Default capacity is 1,000 pending
jobs/project; each scan needs two. Same key/semantic request returns the original,
including after a lost HTTP response, expiry or full queue. Conflict returns 409.
Keys stay reserved with retained history.

Workers claim one due job using `FOR UPDATE SKIP LOCKED`. Each attempt gets a fresh
token/increasing generation. Defaults: heartbeat 2 s, lease 10 s, hard deadline 30 s,
polling 0.5 s, three attempts, exponential retry base 0.5 s and bounded UUID-derived
jitter. Fresh PostgreSQL wall time is sampled after acquiring locks. Expired leases
cannot revive. A heartbeat connection that outlives bounded shutdown stops further
claims instead of accumulating background connections.

Completion/failure lock job, scanner then parent; findings, statuses, attempt history
and audit commit together under ownership checks. Recovery uses the same locks to
authorize expiration and bounded retry/terminal failure. SQL errors roll back;
uncertain ownership expires for recovery. Compute is at least once; publication is fenced.

Scan reads expose scanner version/outcome/coverage plus aggregate status. Job/attempt
rows preserve generation, worker IDs, timings and safe codes. There is no public lease
token endpoint. Phase 1 structured request logging remains; no source, credentials,
request bodies, idempotency keys or driver exceptions are logged. Persisted history
and polling provide diagnostics without adding a metrics service.

## Validation

~~~powershell
uv lock --check
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest -m "unit or api" --basetemp .cache/phase2a-native
docker compose -p asp-phase1-test --profile test up -d --wait test-db
uv run python scripts/validate_phase2a_tests.py
uv run python -m tests.native_windows_snapshots
uv run python scripts/validate_phase2a.py
~~~

The native harness needs Windows symlink privilege (Developer Mode or administrator
shell). Missing privilege exits nonzero with blocked cases, never a Linux skip/pass.
The live helper creates controlled verification records and restarts only the fixed
project API/worker/DB; run when brief local interruptions are acceptable.

The container runner records commands, counts and 25 crash trials in `test-evidence.json`;
raw diagnostics stay ignored in `.cache/phase2a-results/`. Cleanup/downgrades require the
explicit disposable marker plus actual `asp_phase1_test`/`asp_test` identities.
Never run destructive tests concurrently on one test database. Linux CI is a local
workflow definition, not a substitute for Windows evidence; remote workflows were not activated.

## Stop, restart and rollback

~~~powershell
docker compose -p asp-phase1-dev --profile workers stop api worker
docker compose -p asp-phase1-test --profile test stop test-db
docker compose -p asp-phase1-dev up -d --wait db
docker compose -p asp-phase1-dev --profile workers up -d --wait api worker
~~~

Stopping API/worker disables intake/claims and also makes reads unavailable, while
preserving DB, source and attempts. Restart reconciles expired attempts. Never reset
states or delete stuck jobs. To stop the whole deployment, additionally stop its `db`.

Retained development downgrade is refused; prefer compatible forward correction.
The Phase 1 image expects revision 0001 and is not a ready rollback image for 0002.
Restore only an independently approved matching DB/spool pair after verification,
never over retained data automatically. The pre-migration backup contains Phase 1
DB data, not later records/source. DB-only backups cannot restore snapshot bytes.
No prune, `down -v`, repository reset, unrelated-container operation or Matroid change
is part of recovery.
