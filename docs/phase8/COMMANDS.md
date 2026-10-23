# Executed command groups

All commands were local. Secret values and resolved Compose configuration were never
printed. Long command output was captured in ignored `.cache/phase8-*` files; only safe
facts are published. No staging, commit, push, deployment or workflow activation occurred.

The following are the actual validation entry points, with detailed child commands in
their JSON evidence. Paths are relative to the workspace.

```powershell
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe src
uv --cache-dir .cache/phase8-uv lock --check --offline
docker --context desktop-linux info --format '{{.OSType}}'
docker compose -p asp-phase1-test --profile test up -d --wait test-db
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -q -s tests/postgres/test_soc.py
.\.venv\Scripts\python.exe scripts/validate_phase8.py
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -q -s tests/unit tests/api tests/postgres/test_soc.py
.\.venv\Scripts\python.exe -m runner.validate_isolation --phase8
.\.venv\Scripts\python.exe -m runner.validate_scanners --phase8
.\.venv\Scripts\python.exe -m tests.native_windows_snapshots --phase8
.\.venv\Scripts\python.exe -m scripts.validate_phase8_environment
.\.venv\Scripts\python.exe scripts/validate_phase8_browser.py
.\.venv\Scripts\python.exe -m scripts.validate_phase8_rebuild
.\.venv\Scripts\python.exe -m scripts.validate_phase8_state
docker compose -p asp-phase1-dev -f compose.yaml -f compose.phase8.yaml --profile soc config --quiet
git diff --check
```

The full wrapper runs build, container Ruff, container mypy and complete pytest sequentially.
The final affected suite reruns 209 tests after the final nonempty preservation assertions.
The administrator executed the native command separately; its Phase 8 report is verified.

The environment helper executes fixed `docker --context desktop-linux compose --env-file
.local/phase8-demo/environment.env -f compose.phase8-demo.yaml -p asp-phase8-demo` commands:
config --quiet; build api; up db; explicit public and package-local SOC migrations; up
api/soc-worker; four CLI scenarios and exact replays; restart db/api/soc-worker; stop worker;
recreate API with SOC false; stop api/soc-worker/db. It reads guarded inspections without
publishing environment values. Complete command strings are in environment-evidence.json.

The browser helper runs `npm.cmd ci --ignore-scripts --no-audit`, `npm.cmd run build` and
`npm.cmd test -- --grep` with its fixed read-only/security selection and separate Phase 8
report destinations. The clean builder uses `docker build --no-cache --target runtime
--tag asp-phase8/clean:local .`, frozen npm install/build and artifact-hash comparison.
Base images remain digest pinned and cached; no cold registry/image-bit reproducibility
claim is made.

For retained AppSec regression, only its established namespace was started:

```powershell
docker compose -p asp-phase1-dev up -d --wait db
docker compose -p asp-phase1-dev --profile workers --profile triage build api worker triage-worker
docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait api worker triage-worker
```

Before reads, the trusted maintenance helper recorded private public-table fingerprints.
The final read-only state audit compares them and checks migration/admission boundaries.
No retained migration or AppSec write was required. Final shutdown returns the services
started for validation to their initial stopped state, preserving all volumes:

```powershell
docker compose -p asp-phase1-dev --profile workers --profile triage stop api worker triage-worker
docker compose -p asp-phase1-dev stop db
docker compose -p asp-phase1-test --profile test stop test-db
```

An initial focused failure and collection failure were rerun after correction; see
[VALIDATION.md](VALIDATION.md). Inspecting project-only ps/inspect, Git status/diff/ignore
and reading approved specifications were read-only operations. No unscoped resource
cleanup, database reset or Matroid command was executed.
