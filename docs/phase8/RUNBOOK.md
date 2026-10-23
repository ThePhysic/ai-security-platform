# Optional SOC operation and rollback

Default AppSec startup remains the [Phase 7 runbook](../phase7/RUNBOOK.md). No optional
migration, SOC process or SOC environment flag is required. Keep hosted and real-scanner
admission disabled. Never reset the retained database or remove retained volumes.

## Reproduce the isolated demonstration

From the workspace with Docker Desktop Linux containers:

```powershell
uv lock --check
uv sync --frozen
uv run --frozen python -m scripts.validate_phase8_environment
```

The helper creates/preserves private `.local/phase8-demo/environment.env`, builds the
runtime image, starts only Compose project `asp-phase8-demo`, explicitly migrates the
public and SOC schemas, and exercises four synthetic scenarios through the real CLI/API
and separate worker. It verifies review conflicts, actual restart persistence and disabled
routes, then stops its own services without deleting its volume. Repeating it replays
the fixed demo identities and preserves their history. It never touches the retained
AppSec DB/spool. Port 18089 must be free; failures do not authorize stopping its owner.

For interactive use after preparation, enable only this shell's demo flag:

```powershell
$env:ASP_SOC_ENABLED = 'true'
docker compose --env-file .local/phase8-demo/environment.env -f compose.phase8-demo.yaml -p asp-phase8-demo up -d --wait --no-build api soc-worker
```

API is `http://127.0.0.1:18089`. It requires the separately generated demo bearer.
Supply it privately through the trusted local environment, never command arguments,
query strings, logs or committed configuration. The ordinary `asp` CLI reads the main
token; a demo invocation must explicitly select the demo credential in its process.

```powershell
uv run --frozen python -m ai_security_platform.soc.cli --api http://127.0.0.1:18089 demo auth-burst --timeout 30
uv run --frozen python -m ai_security_platform.soc.cli --api http://127.0.0.1:18089 status <run-uuid>
uv run --frozen python -m ai_security_platform.soc.cli --api http://127.0.0.1:18089 history <dataset-uuid>
```

Use `--dataset <uuid> --key <key>` for reproducible replay; omission creates a fresh dataset
and consumes quota. Demo exits 0 for successful correlation execution, 2 for invalid,
operational, timeout or cancellation outcomes. A successful execution with zero matches
is not proof of security. CLI interruption stops local waiting; accepted work remains
durable. History returns a bounded first page and next cursor; the API supports traversal.

## Explicit migration and optional overlay

SOC migrations are independent from the public Alembic history:

```powershell
uv run --frozen alembic -c src/ai_security_platform/soc/alembic.ini upgrade head
```

Run only with the intended database configuration and explicit `ASP_SOC_ENABLED=true`.
Expected optional revision is `soc_0001`; public revision stays `0004_triage_review`.
The demo helper sets both safely. No migration-on-startup behavior exists.

`compose.phase8.yaml` is an optional overlay for the existing development namespace:
combine `-f compose.yaml -f compose.phase8.yaml --profile soc`, migrate SOC explicitly,
then start `api soc-worker` with opt-in. It retains the standard loopback API and
capability-free worker. This overlay was configuration-validated; the isolated demo is
the executed runtime proof. The retained development DB was deliberately not SOC-migrated.
Do not treat this runbook as permission to delete or rewrite established history.

## Disable, stop and recover

For the isolated demo:

```powershell
docker compose --env-file .local/phase8-demo/environment.env -f compose.phase8-demo.yaml -p asp-phase8-demo stop soc-worker
$env:ASP_SOC_ENABLED = 'false'
docker compose --env-file .local/phase8-demo/environment.env -f compose.phase8-demo.yaml -p asp-phase8-demo up -d --wait --no-build api
docker compose --env-file .local/phase8-demo/environment.env -f compose.phase8-demo.yaml -p asp-phase8-demo stop api soc-worker db
Remove-Item Env:ASP_SOC_ENABLED -ErrorAction SilentlyContinue
```

Stop preserves private credentials, volume and history. For interruption recovery, restart
the same compatible worker; expired leases recover with bounded backoff. Read run job
status, attempts and safe error code. Do not erase attempts or manually reset terminal
work. A fresh key creates a new immutable evidence view; it cannot change an older one.
On 409 analyst conflict, fetch current investigation/history and reconsider the edit.

Disabling removes all SOC routes and claims; queued SOC work is retained. AppSec readiness
and public jobs remain independent. Removing the `soc/` package with the flag false is
validated in a separate process using an actual copy without the directory. Optional
schema downgrade/re-upgrade was tested only on the guarded disposable test database,
with unchanged public-table fingerprints. Keep retained SOC data when rolling back;
physical schema deletion requires deliberate review and is not routine recovery.

The Phase 7 maintenance CLI intentionally recognizes only its fixed AppSec/restore/clean
database identities. It does not operate on the SOC demo database. This phase validates
SOC volume persistence, not a new matched SOC backup/restore capability. Protect the
private volume/configuration; do not claim its retention is an independent backup.

## Validation

```powershell
uv run --frozen python scripts/validate_phase8.py
uv run --frozen python -m runner.validate_isolation --phase8
uv run --frozen python -m runner.validate_scanners --phase8
uv run --frozen python -m tests.native_windows_snapshots --phase8
uv run --frozen python scripts/validate_phase8_browser.py
uv run --frozen python -m scripts.validate_phase8_rebuild
```

Native symlink tests require Developer Mode/admin permissions. Integration tests require
the exact guarded disposable `asp-phase1-test` PostgreSQL identity. No mock substitutes
for required PostgreSQL, process or scanner checks. Run scanner probes sequentially with
the host launcher stopped. Browser checks use existing persisted fixtures and require
the default AppSec API and port 18082 free; they do not append retained reviews/triage.
Clean builds exclude private state. Reports go under `docs/phase8/`; earlier reports are
not overwritten. No command activates remote workflows, calls hosted models or changes
Matroid resources.
