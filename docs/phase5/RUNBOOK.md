# Phase 5 local operations

Run from the repository root in PowerShell. Python 3.12 and uv are required; Docker
Desktop must report Linux containers. Keep credentials in ignored local configuration.
Do not print resolved Compose configuration or pass tokens as CLI arguments.

```powershell
uv lock --check
uv sync --locked
docker info --format '{{.OSType}}'
docker compose -p asp-phase1-dev --profile workers --profile triage build api worker triage-worker
docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait api worker triage-worker
```

No Phase 5 migration exists. Verify `0004_triage_review`; apply any earlier pending
forward migration only using its approved runbook. Never downgrade retained development
data. PostgreSQL stays internal; API remains loopback on port 18081.

## Developer workflow

The following placeholders identify operator-authorized local data. Source acquisition
does not execute its contents. Existing quotas and portable-path restrictions apply.

```powershell
uv run --no-sync asp project-create "Authorized local project"
uv run --no-sync asp snapshot-create C:\path\to\authorized-source --label local-review
uv run --no-sync asp snapshot-register --project PROJECT_UUID --key SNAPSHOT_KEY --digest MANIFEST_SHA256
uv run --no-sync asp scan --project PROJECT_UUID --snapshot SNAPSHOT_UUID --idempotency-key UNIQUE_KEY
uv run --no-sync asp scan-status SCAN_UUID
uv run --no-sync asp scan-wait SCAN_UUID --timeout 120
uv run --no-sync asp findings SCAN_UUID --all --limit 100 --max-pages 20
uv run --no-sync asp scan-history --project PROJECT_UUID --limit 50
uv run --no-sync asp policy SCAN_UUID
uv run --no-sync asp export SCAN_UUID --format json --name local-result
uv run --no-sync asp export SCAN_UUID --format sarif --name local-result
```

Real admission remains **disabled by default**. A security-v1 submission returns an
operational error until the approved [Phase 2B runbook](../phase2b/RUNBOOK.md) isolation
proof, scanner assets, explicit admission and live host launcher are satisfied. Do not
enable admission just to obtain a policy pass. The launcher stays a separate trusted
Windows process; API/ordinary workers/scanners never receive daemon authority. Restore
admission disabled and stop only the launcher you started after controlled validation.

For diagnostics, explicitly use `--profile fake-v1` with a locally maintained policy
file containing required scanners `fake-patterns` and `fake-config`,
`allow_synthetic:true`, and a chosen threshold. Such results are labelled synthetic
and provide no actual vulnerability coverage. Historical scan-submit defaults to
fake-v1; the new scan command defaults to security-v1.

Policy/export/scan/wait codes are 0 completed/pass, 1 completed/threshold failure,
2 invalid/operational/incomplete. Use `$LASTEXITCODE` immediately in PowerShell.
Exports may succeed as artifacts even while policy returns 1 or 2. An incomplete required
scanner takes precedence over thresholds. AI review cannot change these codes.
Cancellation and timeout leave accepted server jobs running. Recover a lost submission
response by replaying the same key with identical project/snapshot/profile.

Artifacts appear only under ignored `.local/reports/`; use a fresh safe basename for
each export. Existing files, links and arbitrary output paths are rejected. Review
sanitized metadata before any separately authorized sharing. No automatic SARIF upload
or external source transmission is configured.

## Reproduce validation

See [exact commands](COMMANDS.md), [validation status](VALIDATION.md) and the measured
[workloads](PERFORMANCE.md). These commands are independent of remote Actions:

```powershell
uv run --no-sync ruff check .
uv run --no-sync mypy src
uv run --no-sync python -m runner.validate_isolation --phase5
uv run --no-sync python -m runner.validate_scanners --phase5
uv run --no-sync python scripts/validate_phase5.py
uv run --no-sync python scripts/validate_phase5_ci.py
uv run --no-sync python scripts/validate_phase5_state.py
```

Full tests use namespace asp-phase1-test and the guarded asp_phase1_test/asp_test
database. Its test fixtures intentionally clear disposable records and exercise migration
downgrade/re-upgrade. They never target asp_dev. Do not run concurrent suites against
that same test database. Performance numbers depend on competing host workloads; run
the full suite without concurrent live scanner loads for cleaner comparisons.

Native NTFS proof requires Developer Mode or an administrator shell for symlink fixtures:

```powershell
.\.venv\Scripts\python.exe -m tests.native_windows_snapshots --phase5
```

The accepted Phase 5 artifact records ten passes. An unprivileged blocked result must
never be called a pass. Phase selectors write separate evidence and preserve prior reports.

`validate_phase5_live.py` temporarily enables real admission only for controlled inert
fixtures, adds clearly named retained validation records, runs real CLI subprocesses,
restarts the API/database/workers and tests database unavailability. It restores disabled
admission in finally. Before any new run, preserve the first private retained-row baseline
using `validate_phase5_state.py --record-before` in a fresh validation context; the script
refuses to overwrite an existing baseline. Do not delete the original baseline just to
hide a retention mismatch. Every old row must remain byte-equivalent; new validation rows
are allowed. Actual source snapshots remain retained and count toward the existing quota.

## Restart and rollback

For an ordinary restart, use only this project's explicit namespace:

```powershell
docker compose -p asp-phase1-dev --profile workers --profile triage restart api worker triage-worker db
```

Check `/health` and `/ready` afterward. For an intentionally stopped database:

```powershell
docker compose -p asp-phase1-dev up -d --wait db
```

Keep admission and hosted flags false in ignored configuration. Recreate API/workers
with the approved up command after changing flags. A database outage yields health 200,
readiness 503 and safe data-operation errors; existing workers reconnect and recover.
Do not delete volumes, reset the repository, prune Docker or stop unrelated projects.

Rollback is application-only: restore the previously reviewed Phase 4 CLI/API image or
source and its lockfile through a separately reviewed local change, then rebuild/recreate
only project services. There is **no database downgrade or index reversal**. Existing
scans, findings, triage, consent and human review history remain compatible. Disable
policy enforcement in a consumer independently; retain artifacts and diagnostic reads.
New JSON consumers must account for the additive reporting fields when rolling backward.

No remote workflow has run. Reverting/removing a local workflow definition needs no
remote action here. Optional future code-scanning upload, source transmission or
workflow activation requires separate approval. Stop the disposable test database when
finished using `docker compose -p asp-phase1-test --profile test stop test-db`; preserve
its volume. Follow earlier runbooks for snapshot retention; never bulk-delete the spool.
