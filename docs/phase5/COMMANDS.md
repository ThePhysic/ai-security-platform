# Phase 5 executed validation commands

Commands below ran locally from the workspace root. No Git staging/write, remote
workflow, code-scanning upload, deployment or hosted model call ran. Configuration
and tokens are loaded privately, not embedded in these commands. The wrappers capture
verbose logs under ignored `.cache/phase5-*` and publish bounded sanitized evidence.

## Dependencies and static checks

```powershell
uv add --dev 'jsonschema>=4.23,<5'
uv lock --check
uv sync --locked --offline
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe src
.\.venv\Scripts\python.exe -m pytest tests/unit/test_reporting_cli.py tests/unit/test_guardrails_workflow.py -q --basetemp .cache/phase5-new-unit --tb=short
```

Lock resolution reports 46 packages; the only dependency additions are the development
JSON Schema validator and its locked transitive dependencies. Frozen Docker installations
run in the clean and ordinary test builds. Native targeted checks initially passed 24;
the final container suite includes the subsequent URL-shaped rule rejection test.

## Native and scanner regressions

```powershell
.\.venv\Scripts\python.exe -m tests.native_windows_snapshots --phase5
.\.venv\Scripts\python.exe -m runner.validate_isolation --phase5
.\.venv\Scripts\python.exe -m runner.validate_scanners --phase5
```

The user ran the NTFS command in an administrator shell: 10 passed, 0 blocked/skipped.
Isolation: 31 passed. Real scanner validation checks: 16 passed. Phase 5 selectors keep
prior evidence unchanged. Scanner validation uses private Phase 5 probe/fixture spools,
not relaxed quotas on retained source data.

## HTTP, database, worker and CLI checks

```powershell
.\.venv\Scripts\python.exe scripts/validate_phase5_state.py --record-before
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest tests/postgres/test_reporting.py tests/postgres/test_performance.py -q -s -p no:cacheprovider --tb=short
.\.venv\Scripts\python.exe scripts/validate_phase5_live.py
.\.venv\Scripts\python.exe scripts/validate_phase5.py
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest tests/postgres/test_cli_process.py -q -p no:cacheprovider --tb=short
.\.venv\Scripts\python.exe scripts/validate_phase5_ci.py
.\.venv\Scripts\python.exe scripts/validate_phase5_state.py
```

`validate_phase5.py` executes exactly:

```powershell
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync ruff check .
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync mypy src
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -q -s -p no:cacheprovider
```

The disposable tests apply fresh/repeated/downgrade/re-upgrade migrations and clear
only the guarded test database. Development schema remains unchanged. The live wrapper
builds/recreates only asp-phase1-dev API/worker/triage-worker, starts its own host launcher,
temporarily admits controlled real scans, performs 27 actual CLI subprocess invocations,
restarts project containers, stops/restarts only its development database, and restores
disabled real admission in finally. Its commands, expected and actual exit codes are
recorded in `live-evidence.json` without credentials or source arguments.

The CI wrapper builds an independent clean candidate image, generates the three fixed
artifacts and runs unit/API tests with no network, then removes only its labelled
disposable container. It excludes local instructions/configuration/data from the candidate
copy. Temporary diagnostic copy containers were explicitly scoped and removed.

Read-only version/hardware/container checks used `docker info`, `docker inspect`,
`docker compose version`, private database SELECTs, installed Python distribution metadata
and Windows CIM CPU/memory properties. Retention baselines store private per-row hashes;
public evidence contains only counts and a preservation result. Git diff/check-ignore/
cached-diff checks are read-only.

## Corrected validation failures

These failures were observed and corrected before final gate determination:

| Attempt | Observation | Resolution |
| --- | --- | --- |
| Native NTFS without elevation | Eight passes; two WinError 1314 symlink fixtures blocked | User administrator rerun: ten passes; no requirement weakened |
| Phase 5 isolation child | Child selected historical spool and could not find the probe snapshot | Propagate phase selector to the child; all 31 controls reran |
| New HTTP test | TestClient default Host rejected with 400 | Use the established allowed localhost:8000 test origin |
| Live diagnostic export | Validation basename exceeded 48-character limit; CLI returned 2 | Shorten controlled basename; retain production limit |
| CI archive extraction | Docker cp could not expose tmpfs report files, including while running | Keep bounded ephemeral process alive and extract only three fixed files through bounded stdout |
| Reporting review | URL-shaped scanner rule identities were unnecessarily accepted as text | Reject scheme-shaped identities; add a negative test; rerun affected validation |

Earlier failed logs remain ignored. Final evidence supersedes these attempts, without
rewriting earlier accepted phase results. A Starlette/httpx TestClient deprecation warning
is recorded; it does not change test outcomes and no unrelated dependency upgrade was made.

After final validation, stop only the disposable test database, preserving its volume:

```powershell
docker compose -p asp-phase1-test --profile test stop test-db
```

No `down -v`, prune, unscoped cleanup, database reset or unrelated service operation ran.
