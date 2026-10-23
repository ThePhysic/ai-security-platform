# Phase 2A executed commands

Commands ran from the project workspace. Native executables were also invoked directly
through .venv/Scripts during verification. Docker/uv/native ACL operations used approved
execution outside the restrictive process sandbox when required. No remote workflow ran.

## Environment and dependency validation

~~~powershell
git status --short
git diff --check
git diff --cached --name-only
git check-ignore --quiet AGENTS.md
docker version
docker info
docker compose version
uv --version
uv lock
uv sync --frozen
uv lock --check
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest -m "unit or api" --basetemp .cache/phase2a-final-native -q
~~~

Local instruction reading used an in-memory file read without printing contents.
Documentation/code inspection used Get-Content/rg/git diff on other project files.
Installed Python/package versions were read through importlib.metadata and platform;
all locked versions are copied into runtime-evidence.json.

## Isolated PostgreSQL and final test runner

~~~powershell
docker compose -p asp-phase1-test --profile test up -d --wait test-db
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -m "unit or api or postgres" -q
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest tests/postgres/test_orchestration.py -x -q -s
uv run python scripts/validate_phase2a_tests.py
~~~

The final helper executes build, container Ruff, container mypy and the complete
pytest suite with -q -s -p no:cacheprovider. Exact commands/exit codes and all 25
trial records are in test-evidence.json. Earlier checkpoints recorded 100 passed
(intake/regressions), then 30 passed (first orchestration/25 crashes); final counts
supersede these intermediate runs. Static test failures were corrected and affected
validations rerun, rather than suppressing checks.

Migration generation used Alembic comparison against the explicitly guarded disposable
database. Fresh/head/downgrade/re-upgrade tests execute through pytest/Alembic against
asp_phase1_test/asp_test only. No development downgrade was run.

## Retained migration, native boundary and physical recovery

~~~powershell
uv run python scripts/phase2a_migrate.py
uv run python -m tests.native_windows_snapshots
docker compose -p asp-phase1-dev --profile workers build api worker
docker compose -p asp-phase1-dev --profile workers up -d --wait api worker
uv run python scripts/validate_phase2a.py
docker compose -p asp-phase1-dev exec -T db psql -U asp_owner -d asp_dev -At -c "SHOW server_version"
~~~

The ordinary native harness initially reported blocked symlink privileges; the user
reran that exact command in an administrator shell and generated the passing native
artifact. No system security setting was changed by implementation.

The forward migration helper uses only fixed project resources: identity/count
queries, API stop, pg_dump -Fc to a unique temporary file, docker cp into a private
ignored backup directory, removal of that one temporary file, API/worker build,
explicit alembic upgrade head, retained count comparison and API start.
Its source contains the exact argument arrays; no credentials enter command arguments.

The live helper runs the installed asp CLI to create a controlled fixture/project,
register/submit/replay/query, then restarts API/DB before worker start, starts the worker,
restarts worker/API/DB after completion, stops/starts only that DB to test recovery,
performs guarded inspections and read-only write attempts, and checks sanitized logs.
It records only safe identifiers/booleans in live-evidence.json. Docker exec probes are
trusted fixed Python checks, not target-source execution. No source script is run.

Read-only docker inspect/compose ps/logs were scoped to the two established namespaces.
Final test-db stop preserves its disposable volume. No down -v, host prune, unscoped
deletion, repository reset, staging, commit, push, deployment or Matroid operation ran.
