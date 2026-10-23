# Phase 2B local runbook

Run in the repository root on the validated Windows/NTFS host with Docker Desktop
Linux containers. The API stays at `http://127.0.0.1:18081`. Existing development
namespace is `asp-phase1-dev`; disposable tests use `asp-phase1-test`. Never run
unscoped Docker cleanup, delete retained volumes, reset the repository or touch Matroid.

## Start and migrate

```powershell
uv sync --frozen
uv run python scripts/bootstrap_local.py
uv run asp spool-init
docker --context desktop-linux version
docker compose -p asp-phase1-dev --profile workers config --quiet
docker compose -p asp-phase1-dev up -d --wait db
```

Bootstrap preserves existing credentials and ensures an independent launcher capability
in ignored `.env`; it prints no values. Protect this file and private `.local/` with
the existing local account boundary. Never display resolved Compose configuration.

For retained Phase 2A data, with other writers stopped and real admission disabled:

```powershell
uv run python scripts/phase2b_migrate.py
```

This verifies the exact Compose/database identities, stops only API/worker, takes a
private backup, builds application images, upgrades forward and checks retained row
counts before restarting. It deliberately supports revisions 0002 and 0003 only.
Do not rerun it merely to replace the recorded migration evidence. A new empty DB
instead needs the established explicit `alembic upgrade head` workflow after image
build. Do not downgrade retained development data. Current accepted head is
`0003_scanner_handoff`; old application images may report schema mismatch at readiness.

## Prove isolation before real scanning

Stop the host launcher before validation. The external Docker validation scripts
share the project scanner namespace and must run **sequentially**, never concurrently
with a launcher or one another. PostgreSQL-only tests use their own project.

```powershell
docker --context desktop-linux build --tag asp-phase2b/probe:controlled runner/images/probe
uv run python -m runner.validate_isolation
uv run python -m runner.prepare --reuse-database
uv run python -m runner.validate_scanners
```

On first preparation, omit `--reuse-database` to explicitly download the official
Trivy DB using a separate network-enabled preparation container. Preparation has no
target/source mount or application credentials. Execution never gets network access.
Offline DB reuse verifies recorded hashes; age over 48 hours requires explicit
refresh, updated provenance, coordinated application rebuild and G5 revalidation.
Keep prior images/assets for existing accepted work and historical provenance.

G4 proof is bound to the Windows platform, exact engine identity and boundary file
hash. Changes require a new proof. Any failed or missing proof means keep real
admission disabled; never replace container execution with a host scanner subprocess.
No automatic controlled-only fallback is claimed by this implementation.

## Enable and use real profiles

After G4/G5 pass, set only the nonsecret `ASP_REAL_SCANNING_ENABLED=true` flag in
ignored `.env`, rebuild after registry/code changes, then recreate these project services:

```powershell
docker compose -p asp-phase1-dev --profile workers build api worker
docker compose -p asp-phase1-dev --profile workers up -d --wait api worker
uv run python -m runner.launcher --api http://127.0.0.1:18081
```

Keep the last command running in its own local console. It refuses a second launcher,
checks proof/engine/registry, removes its exact labelled orphans and advertises
availability. An API 503 before a current heartbeat is expected. No database credential
is passed to scanners. API and ordinary workers still have no Docker authority.

Use the existing CLI to create a project, acquire and register an authorized local
source snapshot. Never supply remote repositories or archives. Source files remain data.

```powershell
uv run asp project-create "Local AppSec assessment"
uv run asp snapshot-create C:\path\to\authorized-source --label local-assessment
uv run asp snapshot-register --project PROJECT_UUID --key SNAPSHOT_KEY --digest MANIFEST_SHA256
uv run asp scan-submit --project PROJECT_UUID --snapshot SNAPSHOT_UUID --profile security-v1 --idempotency-key unique-operation-key
uv run asp scan-status SCAN_UUID
uv run asp findings SCAN_UUID
uv run asp scan-history --project PROJECT_UUID --limit 50
```

Replace uppercase placeholders with returned opaque identifiers. CLI loads its public
bearer privately; redirects/proxies are disabled. `fake-v1` remains the default when
`--profile` is omitted and returns explicitly synthetic diagnostic findings. Snapshot
creation does not imply admission or a security result. Public finding-detail and JSON
export routes are documented in `API-AND-SCHEMA.md`; there is no SARIF or upload.

## Reproduce validation

```powershell
uv lock --check
uv sync --frozen
uv run ruff check .
uv run ruff format --check src runner scripts tests migrations
uv run mypy src
uv run python scripts/validate_phase2b_tests.py
uv run python -m pytest -m "unit or api" --basetemp .cache/phase2b-native-validation
uv run python -m tests.native_windows_snapshots --phase2b
uv run python scripts/validate_phase2b_live.py
docker compose -p asp-phase1-test --profile test stop test-db
```

Run the native symlink harness from an administrator shell or a Developer Mode-enabled
account if WinError 1314 occurs. This is a blocked check until it actually runs; never
convert it to a skip. The recorded Phase 2B 10/10 report was provided by the operator's
administrator run. Native pytest also needs permission to access its own protected
temporary snapshot directories. Use a fresh basetemp path; do not delete referenced
published snapshots to reuse one. The Phase 2B flag preserves accepted Phase 2A evidence.

`validate_phase2b_tests.py` builds the isolated image and runs lint/types plus the entire
suite on real PostgreSQL, including 25 separate-process crash experiments and guarded
disposable migration reversal. It retains safe JSON results and ignored local logs.
`validate_phase2b_live.py` uses actual maintained fixtures, containers and PostgreSQL;
it temporarily enables real intake, restarts only these project services, terminates
its own launcher, expires one newly created validation job, checks stale staging and
partial results, then stops its launcher and disables real intake in a finally block.
It preserves created validation records/snapshots. Its named fixture/spool quotas can
eventually be exhausted; do not relax quotas or delete referenced snapshots automatically.

The existing read-only GitHub Actions definition still runs foundation/API/PostgreSQL/
orchestration checks. It does not replace Windows Docker G4/G5 or native filesystem
proofs. No remote workflow was activated.

## Restart, stop and rollback

For a normal restart preserve the DB volume, spool, prepared assets and matching
registry/images. Restart API/worker after DB is healthy; restart the host launcher
with the same verified policy. Lease expiration and bounded retries reconcile killed
workers. Host startup removes exact Phase 2B scanner-labelled orphans before retrying
old handoffs. Do not attach to or reuse an old scanner's output.

To disable new real intake, set `ASP_REAL_SCANNING_ENABLED=false` and recreate API/worker.
Stopping admission alone does not cancel accepted work. For an incident or rollback:
disable intake, stop the dedicated worker, then Ctrl+C the launcher and wait for its
cleanup. If it was killed, with no launcher running use only the ownership-checking
helper below, then verify the project scanner list is empty:

```powershell
docker compose -p asp-phase1-dev --profile workers stop worker
uv run python -c "from pathlib import Path; from runner.boundary import DockerBoundary; DockerBoundary(Path('.local/snapshot-spool')).cleanup_orphans()"
docker --context desktop-linux ps -a --filter label=ai-security-platform.phase2b=scanner --format "{{.Names}} {{.Status}}"
```

The helper inspects every candidate label and removes only owned IDs. If Docker is
unavailable, keep admission/workers stopped and restore Docker before cleanup/restart.
Preserve queued/running jobs, audit history, results, private backup, source snapshots
and prepared assets. Forward-fix at compatible schema; do not force old Phase 2A code
against revision 0003 or destructively downgrade. Database/spool restore remains a
separately planned, verified-target operation; this phase does not claim a full restore
drill. Fake diagnostics can resume on current compatible code after real accepted work
has been accounted for; there is no new automatic per-profile worker-drain mechanism.

At completion the dedicated test DB is stopped, no scanner/host launcher remains, and
API/DB/worker are local with real intake disabled. Retained volumes and evidence remain.
