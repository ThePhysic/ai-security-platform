# Phase 3 executed validation commands

Run from the repository root. Repeated development reruns are represented once;
this is a reproducible command record rather than an export of private shell history.
No actual hosted API request, paid model use, external source transmission, staging,
commit, push, remote deployment or workflow activation was executed.

```powershell
git status --short
git diff --check
git diff --cached --quiet
git check-ignore --quiet AGENTS.md
uv lock --check
uv sync --frozen
.\.venv\Scripts\ruff.exe format src runner scripts tests migrations
.\.venv\Scripts\ruff.exe check . --fix
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe src
.\.venv\Scripts\python.exe -m pytest -m "unit or api" --basetemp .cache/phase3-native-catalog --tb=short
.\.venv\Scripts\python.exe -m tests.native_windows_snapshots --phase3
.\.venv\Scripts\python.exe -m runner.validate_isolation --phase3
.\.venv\Scripts\python.exe -m runner.validate_scanners --phase3
.\.venv\Scripts\python.exe scripts/validate_phase3_tests.py
.\.venv\Scripts\python.exe scripts/phase3_migrate.py
docker compose -p asp-phase1-dev --profile workers --profile triage build api worker triage-worker
docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait api worker triage-worker
.\.venv\Scripts\python.exe scripts/validate_phase3_live.py
.\.venv\Scripts\python.exe scripts/validate_phase3_state.py
docker compose -p asp-phase1-test --profile test stop test-db
```

The operator ran the native NTFS command in an administrator shell after WinError 1314
blocked ordinary symlink fixture creation. Its separate Phase 3 report records 10 passed,
zero blocked. Earlier accepted filesystem/isolation/scanner evidence was not overwritten.
A Windows-only test harness error from an oversized synthetic parameter's generated ID
was corrected with compact case IDs; the oversized payload and rejection requirement
were retained. The corrected native run passed all selected cases.

Migration was first validated in the disposable DB with:

```powershell
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest tests/postgres/test_database.py -q -p no:cacheprovider --tb=short
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -m agent -q -s -p no:cacheprovider --tb=short
```

The full harness executes these exact subcommands and retains their return codes:

```powershell
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync ruff check .
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync mypy src
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -q -s -p no:cacheprovider
```

`test-evidence.json` records all 25 original crash experiments and five new triage
kill/transaction/database-disconnect cases. Additional test cases exercise competing
triage claimers, acceptance/review races, simulated provider failure and stalled-provider
process exit/recovery. Logs are ignored under `.cache/phase3-results/` and are not raw
provider/source traces. One upstream TestClient deprecation warning remains visible.

The migration helper uses the existing project DB identity, `pg_dump -Fc`, a private
backup copy, explicit `alembic upgrade head` and retained-row comparisons. It never
downgrades the development database. Aggregate MD5 row-comparison digests are migration
observations, not replacements for the snapshot protocol's SHA256 identities or a
tamper-proof guarantee. The actual snapshot spool was not rewritten.

The live harness sends authenticated requests only to localhost, selects retained real
controlled Semgrep/Trivy detections, creates independent triage requests, races two
explicit human-review PUTs and physically restarts `api worker triage-worker db` in the
same development project. It compares scan/scanner/finding content before/after and
records no raw source or secret values. Real scanning and hosted transmission stay off.
No generic or unscoped Docker cleanup command was used.
