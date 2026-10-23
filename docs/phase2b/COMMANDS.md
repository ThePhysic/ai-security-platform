# Executed commands and reproducibility

Commands below are the actual command families executed locally for Phase 2B. Repeated
build/test runs during corrections are represented once; this is a reproducibility
record, not a shell-history export. No staging, commit, push, deployment, prune, volume
deletion or remote workflow activation was executed. Commands run in the project root.

## Environment, code and dependency checks

```powershell
git status --short
git diff --stat
git diff --check
git diff --cached --quiet
git check-ignore --quiet AGENTS.md
uv --version
uv lock --check
uv sync --frozen
.\.venv\Scripts\ruff.exe check . --fix
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format src runner scripts tests migrations
.\.venv\Scripts\ruff.exe format --check src runner scripts tests migrations
.\.venv\Scripts\mypy.exe src
.\.venv\Scripts\python.exe -m pytest -m "unit or api" --basetemp .cache/phase2b-native-complete --tb=short
```

Read-only repository/document searches used `rg`, `Get-Content` and file inventories.
Local instructions were read privately and checked unchanged, never printed or staged.
An initial native pytest attempt under the restricted file token could not access its
protected temporary directory; the authorized local rerun passed 97 tests. An ordinary
uv cache-lock denial was likewise resolved by the authorized tool execution context;
no permissions or filesystem safeguards were relaxed.

## Docker readiness and controlled isolation

```powershell
docker --context desktop-linux version
docker --context desktop-linux context inspect desktop-linux --format "{{json .Endpoints.docker.Host}}"
docker --context desktop-linux info --format "{{.OperatingSystem}}"
docker --context desktop-linux build --tag asp-phase2b/probe:controlled runner/images/probe
.\.venv\Scripts\python.exe -m runner.validate_isolation
.\.venv\Scripts\python.exe -m runner.prepare
.\.venv\Scripts\python.exe -m runner.prepare --reuse-database
.\.venv\Scripts\python.exe -m runner.validate_scanners
```

Preparation used digest-pinned upstream images in `policies/scanners.lock.json` and
separate fixed image build contexts. DB preparation ran an explicitly named non-root,
capability-restricted network-enabled container without target mounts or credentials,
copied only generated public DB assets, and removed only that preparation container.
Rebuilds reused the verified DB; no target dependencies were installed or executed.
The controlled probe harness exercised real runtime limits/termination/orphan cleanup.

During development, an attempted parallel live/standalone scanner validation collided
with deliberate launcher orphan cleanup. The standalone suite was rerun sequentially
and passed. Runbook requires exclusive sequential Docker validation. Earlier fixture
and path assumptions were corrected from observed behavior: upstream Semgrep is under
`/usr/bin`, and malformed files without rule-relevant tokens may bypass parsing.
No scanner restriction was weakened to accommodate these corrections.

## Migration, regression and actual application lifecycle

```powershell
.\.venv\Scripts\python.exe scripts/phase2b_migrate.py
.\.venv\Scripts\python.exe scripts/validate_phase2b_tests.py
docker compose -p asp-phase1-dev --profile workers build api worker
docker compose -p asp-phase1-dev --profile workers up -d --wait api worker
.\.venv\Scripts\python.exe scripts/validate_phase2b_live.py
.\.venv\Scripts\python.exe -m tests.native_windows_snapshots --phase2b
.\.venv\Scripts\python.exe scripts/validate_phase2b_state.py
docker compose -p asp-phase1-test --profile test stop test-db
```

The operator ran the native filesystem command in an administrator shell after an
ordinary run reported WinError 1314; its separate Phase 2B artifact records 10 passed,
zero blocked. Accepted Phase 2A evidence was preserved.

`validate_phase2b_tests.py` executes and records these exact subcommands:

```powershell
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync ruff check .
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync mypy src
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -q -s -p no:cacheprovider
```

The live harness launches `python -m runner.launcher --api http://127.0.0.1:18081`,
uses the existing authenticated API transport, restarts `worker api db` through this
Compose project, terminates only its own launcher process, and updates the expiry of
one UUID-validated job it just created. Its stale staging request must return 409.
It stops its own launcher, checks owned orphan cleanup and restores disabled real
admission in `finally`. It never prints lease tokens or authentication values.

Migration subcommands verify `asp_dev:asp_owner`, take `pg_dump -Fc` into a private
backup using the identified project DB container, execute `alembic upgrade head`, and
compare counts. Downgrade/re-upgrade runs only in the disposable PostgreSQL suite.
The retained DB/spool and test volumes are not deleted. Safe final inspection uses
selected `docker inspect` fields; resolved environment values are never reported.

The final coverage-reason addition initially exposed a response-model type mismatch;
the model now explicitly permits validated warning lists and the actual live suite
and affected regressions were rerun. Current artifacts contain passing final runs;
ignored `.cache/phase2b-results/` holds local test diagnostics. An upstream Starlette
TestClient deprecation warning remains visible instead of being suppressed.
