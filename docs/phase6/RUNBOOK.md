# Phase 6 development and rollback

Date: 2026-10-22 (America/Los_Angeles). Run from the workspace root unless noted.
Use the established ignored credentials, immutable spool and retained database.
Do not print resolved Compose config, tokens, source or raw provider data.

## Start the local application

```powershell
docker info --format '{{.OSType}}'
docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait --no-build api worker triage-worker
Push-Location web
npm.cmd ci --ignore-scripts --no-audit
npm.cmd run build
npm.cmd run dev
Pop-Location
```

Node 24.22.1/npm 11.19.1 were validated. npm ci uses the exact package lock and disables
installation hooks. The frontend binds only http://127.0.0.1:18082. API is fixed at
127.0.0.1:18081. Use that precise frontend address; localhost aliases and other origins
are intentionally not admitted. A port collision fails closed. Do not use --host 0.0.0.0,
relax allowedHosts/CORS, add a generic proxy or point this client at an external API.

The API must use the updated Compose exact origin entry. No new image or migration is
needed for this configuration-only backend change; expected schema remains
0004_triage_review. Keep ASP_REAL_SCANNING_ENABLED=false and ASP_HOSTED_ENABLED=false.
No launcher or real scanning is required to investigate accepted persisted findings.

Enter the existing local API bearer in the password field; the application never displays
its value. Obtain it privately from operator configuration, not a URL, shell argument,
screenshot or report. It is held only for the page session and is lost on reload.
Disconnect clears the credential and loaded views. Use a trusted local browser profile;
the dashboard does not protect against a compromised browser, extension or OS administrator.

The accepted controlled demonstration project UUID is
`b4ed7386-d321-4a11-b5d5-29f77f46db0c`. Other UUIDs come from the CLI's project creation
or scan metadata. Open a project,
select a scan, apply optional filters, and inspect a finding. Coverage and synthetic
labels remain part of the result. Detailed scanner metadata is expandable. Initiate
offline triage explicitly; it is not equivalent to live hosted AI reasoning. All advice
requires human verification. Review and save requires confirmation; conflicts require
reading the current server review and explicit reconsideration. Nothing changes source.

## Tests and reproducibility

Keep the dedicated frontend port free before tests; Playwright refuses to reuse an
unknown running server. Stop your own npm dev/preview with Ctrl+C. Do not kill unrelated
Node processes. Browser fixtures use previously accepted Phase 5 controlled scans;
preparation selects a fresh unreviewed finding, preserving all earlier review revisions.

```powershell
.\.venv\Scripts\python.exe scripts/prepare_phase6_browser.py
Push-Location web
npm.cmd ci --ignore-scripts --no-audit
$env:PLAYWRIGHT_BROWSERS_PATH='C:\Users\ridle\ai-security-platform\.cache\phase6-browsers'
node node_modules/@playwright/test/cli.js install chromium --only-shell
npm.cmd run build
npm.cmd test
$env:ASP_TEST_PREVIEW='true'
npm.cmd test
Remove-Item Env:ASP_TEST_PREVIEW
Pop-Location
```

The preparation script reuses controlled IDs and an empty test project in ignored
`.cache/phase6-browser-fixture.json`; it selects a never-reviewed controlled finding on
each new full run. Browser review tests append real records/revisions intentionally.
They do not roll back or clear development history. Available suitable controlled
unreviewed records are finite: exhaustion is an explicit setup failure, not permission
to delete reviews, reset data or enable real scans. Investigations use real deterministic
triage workers. Live hosted calls remain prohibited.

Browser evidence separates genuine API/PostgreSQL workflows from scripted transport
failures/hostile content. The preview case runs compiled assets with the stricter preview
CSP. No default screenshots, videos, traces, raw request bodies or credential-bearing
action logs are retained. The custom reporter emits bounded redacted failures and static
case names; do not replace it with verbose reporters or enable traces using real tokens.

For focused presentation regression without overwriting the full browser report:

```powershell
Push-Location web
$env:PLAYWRIGHT_BROWSERS_PATH='C:\Users\ridle\ai-security-platform\.cache\phase6-browsers'
$env:ASP_TEST_SUPPLEMENTAL='true'
npm.cmd test -- --grep 'exact API origin|history pagination|partial scan|hostile finding|responsive keyboard'
Remove-Item Env:ASP_TEST_SUPPLEMENTAL
Pop-Location
```

The guarded all-in-one frontend validator runs preparation, locked installation, build,
browser availability, full tests and preview sequentially, stopping on any failed prerequisite:

```powershell
.\.venv\Scripts\python.exe scripts/validate_phase6_browser.py
```

Full earlier-phase regressions and native/container proofs:

```powershell
.\.venv\Scripts\python.exe scripts/validate_phase6.py
.\.venv\Scripts\python.exe -m runner.validate_isolation --phase6
.\.venv\Scripts\python.exe -m runner.validate_scanners --phase6
.\.venv\Scripts\python.exe -m tests.native_windows_snapshots --phase6
.\.venv\Scripts\python.exe scripts/validate_phase6_assets.py
.\.venv\Scripts\python.exe scripts/validate_phase6_state.py
```

Native symlink tests require Developer Mode or an administrator shell. The accepted
Phase 6 evidence has ten passes; eight passes plus blocked symlinks is not a pass.
Asset validation requires a built dist folder; it audits only web/package.json, checks
known local credentials/source practices, and records exact versions/build hashes.
Run asset validation again after rebuilding if reporting new asset hashes.

The full backend harness uses only the guarded asp_phase1_test/asp_test database in
asp-phase1-test. It performs destructive migration/fixture exercises **only there**.
Do not run suites concurrently against that database. The retained asp_dev database
must never be reset or downgraded. Stop the test DB without deleting its volume:

```powershell
docker compose -p asp-phase1-test --profile test stop test-db
```

The first retention baseline is private `.cache/phase6-retained-before.json`, recorded
before UI test writes. Do not overwrite it. New validation sessions can use
`validate_phase6_state.py --record-before` only when no baseline exists; preserve existing
baseline evidence if a mismatch appears. Every earlier row must remain byte-equivalent;
new controlled test rows are allowed.

## Preview, restart and rollback

After stopping dev, `npm.cmd run preview` from web/ serves the compiled build on the same
loopback address. It is a local preview, not a deployment or production hosting claim.
Use only one instance on port 18082. Restart frontend by Ctrl+C and rerunning its command.
For a Codex-started server without an interactive terminal, verify its exact workspace
command line and stop only the single matching process before restarting:

```powershell
$uiProcesses = @(Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -like '*C:\Users\ridle\ai-security-platform\web\node_modules*' -and $_.CommandLine -like '*vite*' })
if ($uiProcesses.Count -ne 1) { throw 'Expected one project Vite process; leave processes untouched' }
$uiProcesses | ForEach-Object { Stop-Process -Id $_.ProcessId }
```

Unsaved notes remain in the active selected finding only. Explicit navigation, disconnect
or reload discards them; automatic same-scan status refresh preserves them.

For project backend restart, use the established explicit namespace:

```powershell
docker compose -p asp-phase1-dev --profile workers --profile triage restart api worker triage-worker db
```

Wait for /ready, then reconnect the dashboard and reload records. CLI/API remain usable
independently. Invalid/expired tokens clear the session. API errors show safe generic
messages and do not assume a write succeeded; after uncertain review acceptance, reload
current state before retrying. Preserve the source/DB pairing and existing runbooks.

Rollback: stop only this frontend, use the existing CLI/API, and remove the exact frontend
origin from local Compose configuration through a reviewed change if UI access is no
longer wanted. Recreate only the project API after changing origins. No database migration,
downgrade, review deletion, spool cleanup, image pruning or unrelated service operation
is needed. Retain the locked frontend and sanitized evidence for reproducibility.

No backups/restores, final retention machinery, public deployment, remote workflow
activation or other Phase 7 release work is authorized by this phase.
