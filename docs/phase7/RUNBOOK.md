# Final local operations runbook

Scope: trusted single-operator Windows/NTFS host, Docker Desktop Linux containers, loopback
API/dashboard, deterministic offline triage. Preserve all existing volumes, snapshots,
scanner assets and historical evidence. Never display resolved Compose config or secrets.

## Start or restart the development application

From `C:\Users\ridle\ai-security-platform`:

```powershell
docker --context desktop-linux info --format '{{.OSType}}'
uv lock --check
uv sync --frozen
uv run --frozen python scripts/bootstrap_local.py
uv run --frozen asp spool-init
docker compose -p asp-phase1-dev --profile workers --profile triage config --quiet
docker compose -p asp-phase1-dev --profile workers --profile triage build api worker triage-worker
docker compose -p asp-phase1-dev up -d --wait db
docker compose -p asp-phase1-dev run --rm --no-deps api uv run --no-sync alembic upgrade head
docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait api worker triage-worker
Push-Location web
npm.cmd ci --ignore-scripts --no-audit
npm.cmd run build
npm.cmd run dev
Pop-Location
```

Bootstrap preserves existing ignored credentials; do not replace them for routine restart.
Migration is explicit and remains revision **0004_triage_review**. No Phase 7 migration exists.
Do not downgrade retained data. Missing/mismatched schema keeps readiness unavailable.

API is `http://127.0.0.1:18081`, UI `http://127.0.0.1:18082`. Enter the existing bearer
privately in the UI password field; it remains only in memory. Use the exact address.
Do not widen hosts/origins, bind publicly, persist tokens or put credentials in commands.
For compiled local preview, stop dev and run `npm.cmd run preview` from `web/`.

Keep `ASP_REAL_SCANNING_ENABLED=false` and `ASP_HOSTED_ENABLED=false`. A valid hosted
provider implementation is not authorization to transmit source. Controlled real scanning
requires the [approved launcher runbook](../phase2b/RUNBOOK.md), matching images/policies/DB
and the current Windows containment proof. No untrusted host scanner fallback exists.

For a routine backend restart:

```powershell
docker compose -p asp-phase1-dev --profile workers --profile triage restart api worker triage-worker db
```

Wait for `/ready`, then refresh/reconnect. Expired leases recover through the normal queue;
do not erase stuck jobs or reset statuses. An uncertain review write requires fetching
current revision before another explicit save. Provider failure cannot fail a successful scan.

## Stop safely

Stop your own UI with Ctrl+C. For a Codex-started server, first verify one exact workspace
Vite command; the [Phase 6 runbook](../phase6/RUNBOOK.md) provides the scoped process check.
Never stop every Node or Docker process.

```powershell
docker compose -p asp-phase1-dev --profile workers --profile triage stop api worker triage-worker
docker compose -p asp-phase1-dev stop db
docker compose -p asp-phase1-test --profile test stop test-db
```

These commands retain volumes/data. Do not use down-with-volume-removal, unscoped prune,
repository resets or Matroid operations. Stop any explicitly started host launcher in its
own console and restore disabled admission after controlled scanning.

## Maintenance, backup and restore

Use the full [retention/recovery contract](RETENTION-AND-RECOVERY.md). Initial inspection:

```powershell
uv run --frozen python -m scripts.maintenance retention
uv run --frozen python -m scripts.maintenance artifacts
```

Only explicitly reviewed `retention --apply` removes eligible unregistered seven-day-old
publications. Registered/history sources remain protected. Full quotas stop admission;
they do not authorize deletion or relaxed limits. Export/backup/partial-data inspection is
conservative; unknown ownership fails closed.

Quiesce only this project's API/workers/launcher for the least disruptive backup, keep DB
running, then capture a private receipt and resume compatible services. The implementation
also excludes concurrent DB/spool writes with finite locks. Backup bundles stay private.
No automatic restore into development is supported. Always prepare a fresh explicit
disposable restore instance, verify the trusted manifest digest and check the exact
database/user/project/spool identities before starting its API.

The restore API uses loopback 18087; the clean-build API uses 18088. Their DBs publish no
host ports. Credentials are separate private files. Stop an older restore API before
starting a new instance on the same fixed port; do not alter unrelated listeners.

## Validation and clean rebuild

```powershell
uv run --frozen python scripts/validate_phase7.py
uv run --frozen python -m runner.validate_isolation --phase7
uv run --frozen python -m runner.validate_scanners --phase7
uv run --frozen python -m tests.native_windows_snapshots --phase7
uv run --frozen python -m scripts.validate_phase7_supply_chain
uv run --frozen python scripts/validate_phase7_browser.py
uv run --frozen python scripts/validate_phase7_assets.py
uv run --frozen python scripts/validate_phase7_state.py
```

Native symlinks require Developer Mode or administrator permission. A blocked native
fixture is not a pass. Containment/scanner probes run sequentially with the launcher
stopped; they use maintained controlled images/data only. Never execute source fixtures.

Backend validation uses only the existing guarded `asp-phase1-test` database with explicit
disposable identity checks. Do not run two suites concurrently against it. Downgrade and
fixture cleanup are prohibited on retained development data. Test logs remain private.

Browser tests need port 18082 free and accepted controlled persisted findings. Preparation
selects a fresh unreviewed target and appends real history; repeated runs consume finite
records/quotas. The preview test uses the isolated clean context. Browser captures and
credential-bearing traces are disabled. Genuine and scripted scenarios are labelled.

For a fresh allowlisted build, first build the normal frontend as above, then:

```powershell
uv run --frozen python -m scripts.validate_phase7_rebuild
uv run --frozen python -m scripts.maintenance prepare-sandbox clean
docker --context desktop-linux compose --env-file .local/phase7-clean/environment.env -f compose.phase7.yaml -p asp-phase7-clean up -d --wait db
docker --context desktop-linux compose --env-file .local/phase7-clean/environment.env -f compose.phase7.yaml -p asp-phase7-clean run --rm --no-deps api uv run --no-sync alembic upgrade head
docker --context desktop-linux compose --env-file .local/phase7-clean/environment.env -f compose.phase7.yaml -p asp-phase7-clean up -d --wait --no-build api worker triage-worker
```

The helper creates a new private allowlisted source context, performs uncached application
layers from pinned base images, frozen npm install/build and exact web artifact comparison.
It does not copy local instructions, credentials, backups, snapshots or node_modules.
Image-byte reproducibility and a cold network/base-image cache are not claimed.

The clean retention/recovery helpers operate on deliberately populated test resources and
retain their data. `validate_phase7_retention` expects the initial empty clean schema and
creates controlled diagnostics; it is not a reset command. `validate_phase7_restore` uses
the recorded trusted receipt and initial restored controlled history. For a new drill,
prepare a fresh instance and repeat the guarded restore steps in the recovery contract;
do not delete old history merely to make a helper rerun.

## Rollback and limitations

Stop this frontend or disposable environment; preserve volumes, spool, policies and both
private matched backups. Existing CLI/API remain independent. Use compatible revision-0004
code or a forward fix. Restoration is verified in isolation before any separately reviewed
cutover; no automatic development overwrite or production deployment is implemented.

Do not remove the build hashes or filesystem checks to make a failed rebuild/cleanup pass.
New advisory matches require applicability/severity review. Scanner DB older than 48 hours
requires approved preparation and fresh provenance; never label unavailable coverage clean.

Chromium-only browser coverage, targeted accessibility tests, limited deterministic triage,
two ungraded Kubernetes bindings and A13 unsupported advisory remediation remain explicit.
Public hosting, live hosted models, Phase 8 and Matroid work need separate authorization.
