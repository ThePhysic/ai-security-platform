# Phase 1 completion report

Date: 2026-10-22 (America/Los_Angeles).
**G1: PASSED locally. Phase 1 only; Phase 2A NOT AUTHORIZED.**

The user explicitly authorized Phase 1 file changes, dependencies and project-scoped validation. Phase 0 documents remain the historical design baseline and were not rewritten during implementation. No application work from Phase 2A or later was performed. No staging, commits, pushes, deployment, external provisioning or remote workflow activation occurred.

## Delivered behavior

Python/FastAPI foundation with synchronous DB handlers/sessions, safe startup/settings, local bearer access, exact Host/Origin policy, request/header/body-time bounds, sanitized errors, allowlisted structured logs and correlation IDs. Explicit migration 0001_foundation creates only projects, source_snapshots, scan_runs and audit_events. Snapshot/scan metadata has no public creation/submission API. Project creation and its audit event commit atomically.

Five endpoints only: GET /health; GET /ready; POST /api/v1/projects; GET /api/v1/projects/{project_id}; GET /api/v1/scan-runs/{scan_id}. Public health checks reveal only coarse state; data endpoints authenticate. Interactive docs/OpenAPI routes are disabled, with generated schema tested offline.

Non-root API container UID/GID 10001:10001, read-only root filesystem, dropped capabilities, no privilege escalation, loopback 18081 publication and no Docker/home/credential bind mounts. PostgreSQL is internal-only. Test services use a separate namespace, credential, database and named volume. Local instruction files, configuration and Git data are explicitly excluded from build context.

## Exact versions and provenance

| Component | Version |
|---|---|
| Python, native project and container | 3.12.15 |
| uv, native and build image | 0.13.5 |
| PostgreSQL | 17.11 (Debian 17.11-1.pgdg12+2) |
| FastAPI / Starlette | 0.161.0 / 1.9.0 |
| Pydantic / settings | 2.14.1 / 2.16.1 |
| SQLAlchemy / Alembic | 2.0.55 / 1.20.1 |
| Psycopg / binary | 3.3.6 / 3.3.6 |
| Uvicorn | 0.54.0 |
| pytest / HTTPX | 9.1.1 / 0.28.1 |
| Ruff / mypy | 0.17.2 / 1.20.2 |
| PyYAML / typing stubs | 6.0.3 / 6.0.12.20260906 |
| Docker engine / Compose | 29.9.1 / 5.6.0 |
| Migration revision | 0001_foundation |

PyYAML/stubs support infrastructure/CI policy tests, not application infrastructure. See [native dependency inventory](dependency-versions.json) for all installed package versions and uv.lock for cross-platform resolution/integrity hashes. Windows-only packages are absent from Linux where not selected by markers.

Pinned OCI index digests:
- Python: sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
- PostgreSQL: sha256:858bb5e98eed02eb8cafbcdc007f9a65d1b613972028944a8ec2133ccaf80d27
- uv: sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff

Exact source/dependency/base-image inputs are recorded; no claim of byte-identical image output across builds is made. Build backend resolution uses standard isolated Python packaging. Runtime/dev dependencies use the frozen lock.

## Acceptance results

| Check | Final result |
|---|---|
| uv lock creation, frozen install and final lock check | Passed |
| Ruff on native project and Linux test image | Passed |
| mypy strict on native project and Linux test image | Passed, 24 source files |
| Unit tests | 21 passed |
| API tests | 26 passed |
| Real PostgreSQL tests | 25 passed |
| Full Linux PostgreSQL-backed suite | **72 passed, 0 failed, 0 skipped** |
| Final native unit/API run | 47 passed, 25 intentionally deselected |
| Migration from empty, repeated head, guarded downgrade/re-upgrade, autogeneration drift check | Passed |
| Missing DB/wrong schema and DB-independent liveness | Passed |
| Live project persistence after API and database container restarts | Passed |
| Live test-only scan metadata after API and database container restarts | Passed |
| Live access, log redaction, non-root/read-only/capability/port/mount checks | Passed |
| CI definition permissions/actions/required-marker policy | Passed; remote GitHub execution not performed |
| Final generated-credential scan of Git-visible files | Passed, zero matches; local instructions unchanged/ignored/unstaged |

One upstream Starlette/HTTPX test-client deprecation warning remains. It is not suppressed, and no required check was skipped. The full suite passed in 2.62 seconds on this run; this is test runtime, not an application performance SLO. Marker counts were verified by collection; each existing test belongs to a required Phase 1 group.

See [sanitized live evidence](validation-evidence.json). Live checks ran against Docker Desktop Linux containers on Windows, not just reopened ORM sessions. No volume was removed. Only fixed asp-phase1-dev / asp-phase1-test resources were mutated; the temporary test API probe was removed after validation.

## Commands executed

Commands are listed once per distinct verification form; several were rerun after affected fixes. No credential values were placed in the command text.

~~~text
py -3.12 --version
uv --version
uv python list --only-installed
uv lock
uv sync --frozen
uv lock --check

.\.venv\Scripts\python.exe scripts/bootstrap_local.py
.\.venv\Scripts\ruff.exe check . --fix
.\.venv\Scripts\ruff.exe format .
.\.venv\Scripts\ruff.exe check --no-cache .
.\.venv\Scripts\ruff.exe check --no-cache src tests scripts migrations --fix
.\.venv\Scripts\ruff.exe format --no-cache src tests scripts migrations
.\.venv\Scripts\mypy.exe src
.\.venv\Scripts\python.exe -m pytest -m 'unit or api' -q
.\.venv\Scripts\python.exe -m pytest -m 'unit or api' -q -p no:cacheprovider
.\.venv\Scripts\python.exe -m pytest --collect-only -m unit -q
.\.venv\Scripts\python.exe -m pytest --collect-only -m api -q
.\.venv\Scripts\python.exe -m pytest --collect-only -m postgres -q

docker version --format '{{.Client.Version}} {{if .Server}}{{.Server.Version}} {{.Server.Os}}{{end}}'
docker compose version
docker ps --format '{{.Names}}'
docker buildx imagetools inspect python:3.12-slim-bookworm
docker buildx imagetools inspect postgres:17-bookworm
docker buildx imagetools inspect ghcr.io/astral-sh/uv:0.13.5
docker buildx imagetools inspect postgres:17-bookworm --format '{{.Manifest.Digest}}'
docker compose -p asp-phase1-dev config --quiet
docker compose -p asp-phase1-test --profile test config --quiet
docker compose -p asp-phase1-dev build api
docker compose -p asp-phase1-dev up -d --wait db
docker compose -p asp-phase1-dev run --rm api uv run --no-sync alembic upgrade head
docker compose -p asp-phase1-dev up -d --wait api
docker compose -p asp-phase1-test --profile test up -d --wait test-db
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -m postgres -q
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -q
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync ruff check .
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync mypy src
docker compose -p asp-phase1-dev exec -T db postgres --version
docker compose -p asp-phase1-dev exec -T api python --version
docker compose -p asp-phase1-dev ps --format json
docker compose -p asp-phase1-test --profile test stop test-db
docker compose -p asp-phase1-dev exec -T db psql -U asp_owner -d asp_dev -Atc 'SELECT version_num FROM alembic_version;'
.\.venv\Scripts\python.exe scripts/validate_local.py
~~~

The validation helper executes the exact fixed project restart/stop/start, safe inspect, HTTP, test-fixture and temporary-probe commands in [its source](../../scripts/validate_local.py). Migration tests invoke upgrade/check/downgrade through Alembic's Python API under disposable identity guards. Read-only Git status/diff/ignore checks and credential-free version/hash inventory checks were also performed. No Git mutation commands ran.

## Findings corrected during validation

- Sandbox denied Docker/uv cache access; affected commands were rerun with approved escalation. No remaining execution block.
- An early infrastructure assertion incorrectly treated an internal Docker build stage as an external unpinned image; corrected to check external image provenance.
- The live helper initially lacked the repository import path; corrected, and its temporary probe cleanup was verified.
- A real stopped-DB check exposed Docker DNS delay beyond libpq connect_timeout. Added a synchronous wall-clock readiness guard with at most one in-flight daemon probe. The new hung-dependency test and actual outage/restart checks pass.
- Early lint/type issues were corrected. Final static checks and full tests pass.

## Design refinements, limits and remaining risks

No approved architecture was replaced. A storage/readiness module is a justified small file split; its single bounded dependency probe is not a durable worker, queue, leasing or retry system. Test metadata lives only in the disposable namespace. Named test storage is deliberately restart-persistent but still guarded as disposable. PyYAML is a development-only policy-check dependency. Pytest cache is disabled to avoid Windows sandbox temporary-cache permission noise; no security/integration test is disabled.

Local single-user authentication is not tenancy/RBAC or public-hosting security. Secrets remain in ignored local configuration and trusted container environments; Docker/host administrators are outside the protection claim. Windows ACLs are inherited. The one underlying OS/DNS probe may finish after an HTTP timeout; further checks cannot spawn more in-flight probes. Dependency upgrades need review because of the HTTPX deprecation warning.

Scanner isolation, snapshot acquisition, durable job fencing, hosted model privacy and production reliability remain unimplemented later-phase gates. No source scanning, prompt transmission or target code execution occurred. Phase 7 restore/retention is not claimed here.

## Safe restart and rollback

Follow [RUNBOOK](RUNBOOK.md). Restart only the named project's services and preserve volumes/configuration. Initial destructive downgrade is refused outside asp_phase1_test with asp_test and the explicit disposable marker. Keep development data and use a verified backup/compatible forward fix instead of reset. No down -v, prune or unrelated resource cleanup is authorized.

Development API and DB remain running and healthy for review on loopback port 18081; development PostgreSQL has no host port. The disposable test database is stopped with its separate volume retained, and the temporary probe is removed. Final development revision is 0001_foundation. No remote CI workflow is active.

## Phase 2A handoff — NOT AUTHORIZED

After separate approval, add secure immutable local snapshot intake and minimal CLI, atomic idempotent acceptance, scanner execution/job/attempt records, deterministic fake adapter, PostgreSQL SKIP LOCKED claims, generation/token leases, bounded retries/backoff/heartbeat/recovery, fenced result/state/audit publication and cursor history. Validate G2/G3 and at least 25 controlled crash/retry trials with real PostgreSQL. Preserve current authentication/error/session contracts and add migrations forward.

Do not integrate real scanners or host launcher before separately authorized Phase 2B. No agents/reviews/UI/SOC/Matroid changes belong to Phase 2A. This handoff does not authorize beginning it.

## Created and modified files

The inventory below covers Phase 1 source/configuration/tests/documentation only. Pre-existing untracked Phase 0 documents are preserved, not counted as newly created by this phase. Ignored local outputs include generated .env credentials, the project virtual environment and tool/build caches; their contents are never included in reports.

| File | Change |
|---|---|
| [.dockerignore](../../.dockerignore) | Created |
| [.env.example](../../.env.example) | Created |
| [.github/workflows/ci.yml](../../.github/workflows/ci.yml) | Created |
| [.gitignore](../../.gitignore) | Modified |
| [.python-version](../../.python-version) | Created |
| [alembic.ini](../../alembic.ini) | Created |
| [compose.yaml](../../compose.yaml) | Created |
| [Dockerfile](../../Dockerfile) | Created |
| [docs/phase1/COMPLETION-REPORT.md](../../docs/phase1/COMPLETION-REPORT.md) | Created |
| [docs/phase1/dependency-versions.json](../../docs/phase1/dependency-versions.json) | Created |
| [docs/phase1/RUNBOOK.md](../../docs/phase1/RUNBOOK.md) | Created |
| [docs/phase1/validation-evidence.json](../../docs/phase1/validation-evidence.json) | Created |
| [migrations/env.py](../../migrations/env.py) | Created |
| [migrations/script.py.mako](../../migrations/script.py.mako) | Created |
| [migrations/versions/0001_foundation.py](../../migrations/versions/0001_foundation.py) | Created |
| [pyproject.toml](../../pyproject.toml) | Created |
| [README.md](../../README.md) | Modified |
| [scripts/bootstrap_local.py](../../scripts/bootstrap_local.py) | Created |
| [scripts/validate_local.py](../../scripts/validate_local.py) | Created |
| [src/ai_security_platform/__init__.py](../../src/ai_security_platform/__init__.py) | Created |
| [src/ai_security_platform/api/__init__.py](../../src/ai_security_platform/api/__init__.py) | Created |
| [src/ai_security_platform/api/app.py](../../src/ai_security_platform/api/app.py) | Created |
| [src/ai_security_platform/api/dependencies.py](../../src/ai_security_platform/api/dependencies.py) | Created |
| [src/ai_security_platform/api/errors.py](../../src/ai_security_platform/api/errors.py) | Created |
| [src/ai_security_platform/api/routes/__init__.py](../../src/ai_security_platform/api/routes/__init__.py) | Created |
| [src/ai_security_platform/api/routes/health.py](../../src/ai_security_platform/api/routes/health.py) | Created |
| [src/ai_security_platform/api/routes/projects.py](../../src/ai_security_platform/api/routes/projects.py) | Created |
| [src/ai_security_platform/api/routes/scan_runs.py](../../src/ai_security_platform/api/routes/scan_runs.py) | Created |
| [src/ai_security_platform/api/security.py](../../src/ai_security_platform/api/security.py) | Created |
| [src/ai_security_platform/config.py](../../src/ai_security_platform/config.py) | Created |
| [src/ai_security_platform/domain/__init__.py](../../src/ai_security_platform/domain/__init__.py) | Created |
| [src/ai_security_platform/domain/errors.py](../../src/ai_security_platform/domain/errors.py) | Created |
| [src/ai_security_platform/domain/projects.py](../../src/ai_security_platform/domain/projects.py) | Created |
| [src/ai_security_platform/domain/scans.py](../../src/ai_security_platform/domain/scans.py) | Created |
| [src/ai_security_platform/domain/snapshots.py](../../src/ai_security_platform/domain/snapshots.py) | Created |
| [src/ai_security_platform/logging.py](../../src/ai_security_platform/logging.py) | Created |
| [src/ai_security_platform/main.py](../../src/ai_security_platform/main.py) | Created |
| [src/ai_security_platform/storage/__init__.py](../../src/ai_security_platform/storage/__init__.py) | Created |
| [src/ai_security_platform/storage/base.py](../../src/ai_security_platform/storage/base.py) | Created |
| [src/ai_security_platform/storage/models.py](../../src/ai_security_platform/storage/models.py) | Created |
| [src/ai_security_platform/storage/readiness.py](../../src/ai_security_platform/storage/readiness.py) | Created |
| [src/ai_security_platform/storage/repositories.py](../../src/ai_security_platform/storage/repositories.py) | Created |
| [src/ai_security_platform/storage/session.py](../../src/ai_security_platform/storage/session.py) | Created |
| [tests/__init__.py](../../tests/__init__.py) | Created |
| [tests/api/test_contracts.py](../../tests/api/test_contracts.py) | Created |
| [tests/conftest.py](../../tests/conftest.py) | Created |
| [tests/db_guard.py](../../tests/db_guard.py) | Created |
| [tests/postgres/conftest.py](../../tests/postgres/conftest.py) | Created |
| [tests/postgres/test_database.py](../../tests/postgres/test_database.py) | Created |
| [tests/probe_server.py](../../tests/probe_server.py) | Created |
| [tests/restart_fixture.py](../../tests/restart_fixture.py) | Created |
| [tests/unit/test_infrastructure.py](../../tests/unit/test_infrastructure.py) | Created |
| [tests/unit/test_settings.py](../../tests/unit/test_settings.py) | Created |
| [uv.lock](../../uv.lock) | Created |
