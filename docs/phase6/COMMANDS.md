# Executed Phase 6 commands

All execution was local. No Git staging/commit/push, remote workflow, hosted model call,
target repository execution, public deployment or unrelated resource modification ran.
The [runbook](RUNBOOK.md) supplies ordered reproduction and prerequisites. Credentials
are loaded privately from ignored operator configuration, never command-line values.

## Frontend dependencies, build and browser

Exact package versions were resolved with npm view for React, React DOM, TypeScript,
Vite, Playwright and their type packages. Installation/build from **web/**:

```powershell
npm.cmd install --ignore-scripts --no-audit
npm.cmd ci --ignore-scripts --no-audit
npm.cmd run build
npm.cmd audit --json
$env:PLAYWRIGHT_BROWSERS_PATH='C:\Users\ridle\ai-security-platform\.cache\phase6-browsers'
node node_modules/@playwright/test/cli.js install chromium --only-shell
npm.cmd test
$env:ASP_TEST_SUPPLEMENTAL='true'
npm.cmd test -- --grep 'exact API origin|history pagination|partial scan|hostile finding|responsive keyboard'
Remove-Item Env:ASP_TEST_SUPPLEMENTAL
$env:ASP_TEST_PREVIEW='true'
npm.cmd test
```

`npm run build` runs strict `tsc --noEmit` then Vite. The final production output is
three files; exact byte sizes/hashes are in `frontend-evidence.json`. Locked reinstall
succeeded without lifecycle hooks. The correctly scoped full web audit reports zero
advisories; an earlier root-directory audit resolved an ancestor manifest and was
discarded without changing any ancestor files or dependencies.

The guarded validator records six successful prerequisite/build/browser commands in
frontend-command-evidence.json and stops on any failed step. The full browser run passed 19 cases. Five affected presentation/security scenarios
reran after final layout changes, separately recorded in layout-evidence.json. The
compiled preview passed one additional scenario. No default reporter/traces/videos/
screenshots were enabled. Two manual private visual captures used only controlled
record metadata after the password field had left the DOM; they are not published.

## Project services and integration fixtures

From the workspace root:

```powershell
docker info --format '{{.OSType}} {{.ServerVersion}}'
.\.venv\Scripts\python.exe scripts/validate_phase6_state.py --record-before
docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait --no-build api worker triage-worker
.\.venv\Scripts\python.exe scripts/prepare_phase6_browser.py
.\.venv\Scripts\python.exe scripts/validate_phase6_browser.py
.\.venv\Scripts\python.exe scripts/validate_phase6_assets.py
.\.venv\Scripts\python.exe scripts/validate_phase6_state.py
```

Only the API was recreated for the new exact frontend Origin; worker/triage/database
services and retained data continued. Browser preparation reads accepted controlled
Phase 5 scans and creates/reuses one empty project, fresh review-target identifiers and
a harmless ignored private-file denial probe. It never executes source or scans.

Actual browser actions add deterministic triage runs and confirmed human review revisions
to previously unreviewed controlled findings. Two-window conflict tests prove revision 0
creation, first writer success, stale second writer 409 and explicit reconsideration.
Additional controlled API writes populate history pagination. No original review/history
was edited or removed. Native source snapshots, scanner runs/findings and launcher
provenance remain unchanged in the development DB.

Manual `npm run dev` served only 127.0.0.1:18082 for visual review. For preview testing,
only the single verified Vite process with this workspace's web/node_modules path was
stopped. No general Node/Docker cleanup was used. See the runbook for normal Ctrl+C
shutdown and separate preview startup.

## Earlier-phase regressions

```powershell
.\.venv\Scripts\python.exe scripts/validate_phase6.py
.\.venv\Scripts\python.exe -m runner.validate_isolation --phase6
.\.venv\Scripts\python.exe -m runner.validate_scanners --phase6
.\.venv\Scripts\python.exe -m tests.native_windows_snapshots --phase6
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe src
git diff --check
```

The backend wrapper executes:

```powershell
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync ruff check .
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync mypy src
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -q -s -p no:cacheprovider
```

Result: 256 passed, 0 failed/skipped, including 25 scan crash/retry and five triage
process/database recovery experiments. The guarded disposable DB alone receives
migration downgrade/re-upgrade/fixture cleanup. Native NTFS initially had two blocked
symlink fixtures; the user's administrator command produced ten passes. Real container
isolation returned 31 passes and real scanner validation 16 passes.

Read-only final checks inspected scoped container restrictions, installed versions,
original row hashes, unchanged frozen quality/attack outcomes, protected instruction
hash/ignore rules and empty staging. They never print credential or instruction content.
Raw backend test logs remain under ignored `.cache/phase6-results/`; all published
reports are sanitized. No prior phase evidence was overwritten.

The disposable test database is stopped with its volume retained:

```powershell
docker compose -p asp-phase1-test --profile test stop test-db
```

Development services and the final local frontend remain available. Real scanner and
hosted admission remain disabled; no host launcher/scanner orphan remains. No prune,
unscoped volume deletion, retained database reset or repository reset ran.
