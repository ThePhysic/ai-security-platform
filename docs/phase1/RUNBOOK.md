# Phase 1 local runbook

Phase 1 implements only the authenticated API/PostgreSQL foundation. No source intake, scan submission, jobs, scanners, AI, review, SARIF or UI exists. Phase 2A needs separate authorization. See the [completion report](COMPLETION-REPORT.md), [live evidence](validation-evidence.json) and [contract](../phase0/09-PHASE1-SPECIFICATION.md).

## Prerequisites and isolation

Windows, Docker Desktop Linux engine, uv 0.13.5 and Python 3.12.15. Use the explicit development namespace asp-phase1-dev and test namespace asp-phase1-test. Images and dependencies are pinned in Dockerfile, compose.yaml and uv.lock. Native lint/unit/API checks use the project environment; PostgreSQL checks run in the test image.

Do not operate on Matroid resources or run unscoped prune/reset/volume-removal commands. PostgreSQL is not host-published. API defaults to http://127.0.0.1:18081 with exact local Origin/Host allowlists.

## Setup and explicit migrations

Run from the repository root:

~~~powershell
uv sync --frozen
uv run python scripts/bootstrap_local.py
docker version
docker compose -p asp-phase1-dev config --quiet
docker compose -p asp-phase1-dev build api
docker compose -p asp-phase1-dev up -d --wait db
docker compose -p asp-phase1-dev run --rm api uv run --no-sync alembic upgrade head
docker compose -p asp-phase1-dev up -d --wait api
~~~

Bootstrap creates ignored .env once with independent random database/test/bearer credentials, prints no values and preserves existing configuration. It refuses a non-ignored destination. Keep the file private; Windows protection depends on inherited NTFS ACLs. Do not render resolved Compose configuration into logs. The example file has no usable credentials. Never regenerate credentials against an existing volume; restore matching configuration or rotate them deliberately.

No DB connection/migration occurs at import/startup. Missing or mismatched schema yields readiness 503 until explicitly migrated. Runtime/migration commands use --no-sync and do not install packages.

## Supported API

| Operation | Result |
|---|---|
| GET /health | Public 200 process liveness |
| GET /ready | Public 200 expected schema, otherwise sanitized 503 |
| POST /api/v1/projects | Authenticated 201; project and audit commit together |
| GET /api/v1/projects/{id} | Authenticated 200 or 404 |
| GET /api/v1/scan-runs/{id} | Authenticated persisted metadata only, or 404 |

Read the bearer from ignored configuration into your client without printing it, putting it in URLs/history, or embedding it in committed files/browser storage. The validation helper demonstrates authenticated calls safely.

Future routes are absent. Interactive/network OpenAPI endpoints are disabled; tests validate generated schema, bearer requirements and error models. Envelopes contain code, message, request_id, retryable, details, with no input echo. Expect 401 bearer failure, 403 denied Origin, 400 denied Host, 413 oversized body/header, 422 invalid payload, and sanitized 500/503.

## Validation

~~~powershell
uv lock --check
uv sync --frozen
uv run ruff check .
uv run mypy src
uv run pytest -m unit
uv run pytest -m api

docker compose -p asp-phase1-test --profile test config --quiet
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test up -d --wait test-db
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -q
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync ruff check .
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync mypy src
uv run python scripts/validate_local.py
~~~

Full pytest selects all Phase 1 tests. Missing PostgreSQL is a failure, never a green skip. Native postgres-marker tests need an explicit guarded test URL; never substitute the development DB. Test DB volume is separate and disposable. Tests check the URL, marker, actual database and role before cleanup/reversal. Initial downgrade itself checks asp_phase1_test/asp_test and refuses development reversal.

The live helper requires both built images, migrated databases and running development API. It restarts/stops only fixed project-owned resources, creates a real development project and guarded test-only scan metadata, checks recovery/logs/container restrictions, removes its temporary API probe and writes sanitized evidence. Verification projects and test metadata remain as validation data; no source was acquired. Temporary test API uses loopback port 18082, which must be free; an existing probe name is never replaced.

Do not run migration/cleanup tests concurrently on one disposable DB. CI defines serial checks in its own namespace, pinned checkout and read-only permissions; no uploads/deployments/provider keys. Remote CI was not activated.

## Readiness and safe logging

Readiness has a wall-clock limit in addition to DB connect/statement timeouts. Docker DNS can outlast libpq connect_timeout when a service stops. At most one daemon probe is in flight per application; timed-out HTTP checks return 503 while it finishes. No probe queue, persistent work, retry machinery or business jobs are introduced. Database handlers/sessions stay synchronous. Liveness remains DB-independent.

Logs allow only event, safe request ID, method, registered route template, status and duration. Uvicorn access logs/proxy headers are disabled. Exception/input/connection details, raw queries/bodies/auth headers and project names are excluded. No raw source enters this phase.

## Safe restart, stop and rollback

~~~powershell
docker compose -p asp-phase1-dev restart db
docker compose -p asp-phase1-dev up -d --wait api
docker compose -p asp-phase1-dev restart api
docker compose -p asp-phase1-test --profile test stop test-db
docker compose -p asp-phase1-dev stop api db
~~~

Stop preserves project volumes. Start again with matching configuration and up -d --wait. Initial reversal is destructive and prohibited on development data. No down -v, prune or automatic reset is a recovery step. Preserve verified backups and prefer compatible forward correction on retained data. Future incompatible changes need a separate rollback plan. Matched DB/spool backup/restore belongs to Phase 7; no source spool exists yet.

## Known limits

Single-user bearer access is not tenancy/enterprise identity. Docker administrators can inspect environment credentials. A timed-out OS DNS call may continue inside the one outstanding daemon probe. No production SLO or scanner containment claim is made. Locked Starlette emits an HTTPX test-client deprecation warning; tests pass without suppressing it. Reassess compatibility before dependency upgrades.
