# Phase 1 Implementation Specification

Status: **Implementation-ready planning; NOT YET AUTHORIZED.** This specification does not permit file creation, dependency installation or service execution now. The ready-to-paste future implementation prompt is in [07](07-CODEX-PHASE0-HANDOFF.md).

## Objective and boundary

Deliver the authenticated local Python API and PostgreSQL lifecycle foundation, with typed contracts, safe logging/errors, explicit migrations and reproducible tests. The architecture is approved; implement only this phase after explicit authorization. Stop at G1; do not begin Phase 2A.

Use Python 3.12, uv, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, Psycopg 3 and PostgreSQL with synchronous DB sessions. No queue, scanner or model execution. A future scan is asynchronous because workers will process durable jobs, not because the HTTP handler uses `async def`.

## Files and ownership

Paths below are the intended Phase 1 implementation surface, not files to create during Phase 0. Choose compatible exact package patches/image digests during implementation and record them. Small justified file splits within these modules are allowed; report deviations.

| Files/modules | Responsibility |
|---|---|
| `pyproject.toml`, `uv.lock`, `.python-version` | Python 3.12 requirement/pin, declared runtime/dev dependencies, lint/type/pytest config and markers |
| `src/ai_security_platform/__init__.py`, `main.py` | App factory/export for ASGI; no import-time connections/migrations |
| `config.py` | Typed validated settings; fail safely on missing secrets/invalid policy; no printing full settings |
| `logging.py` | Structured allowlisted events and request correlation; safe exception categories |
| `api/app.py`, `dependencies.py`, `security.py`, `errors.py` | App wiring, synchronous sessions, bearer auth, Host/Origin controls, safe errors and request limits |
| `api/routes/health.py`, `projects.py`, `scan_runs.py` | Only the Phase 1 routes listed below |
| `domain/projects.py`, `snapshots.py`, `scans.py`, `errors.py` | Typed request/read contracts, IDs/enums/provenance and domain errors |
| `storage/base.py`, `session.py`, `models.py`, `repositories.py` | Declarative base, engine/session factory, four metadata tables, scoped persistence transactions |
| `alembic.ini`, `migrations/env.py`, `migrations/script.py.mako`, `migrations/versions/0001_foundation.py` | Explicit initial schema; no secret in migration config; expected revision check |
| `Dockerfile`, `compose.yaml`, `.dockerignore`, `.env.example` | Non-root app image, local API/DB and isolated test profile; no private files in build context; examples without real secrets |
| `tests/conftest.py`, `tests/unit/`, `tests/api/`, `tests/postgres/` | Test settings/factories, HTTP security/error tests and real PostgreSQL lifecycle tests |
| `.github/workflows/ci.yml` | Local workflow definition for lint/type/unit/API/PostgreSQL checks; no remote activation/upload |
| `docs/phase0/` validation notes and a focused implementation runbook under `docs/` | Exact commands, environment prerequisites, test results, known limits and Phase 2A handoff |
| `README.md` | Update stale status and link runbook during authorized Phase 1 only |

Root `AGENTS.md` is never modified, staged or exposed. Do not rewrite other existing root files without need. An implementation may add narrowly necessary ignore patterns for generated local files; existing credential exclusions must be preserved.

Runtime dependencies: approved stack plus Uvicorn and typed settings support as needed. Development dependencies: pytest, HTTPX, Ruff and mypy; add typing support only where necessary. Do not add an agent SDK/framework, scanner binaries, Redis client, Node dependencies, Celery, test-container framework or observability platform. Tests use explicit Compose PostgreSQL, not Docker daemon access from the application.

## Initial schema

Create exactly these application tables plus Alembic's revision table:

1. `projects`: UUID PK, bounded display `name`, timezone-aware `created_at`.
2. `source_snapshots`: UUID PK, project FK, bounded relative opaque spool key, manifest version/digest, content digest, inclusion-policy digest, provenance kind/label, non-negative byte/file counts, created_at and retention state. Unique `(project_id, content_digest, manifest_version)` and project/snapshot association key. No raw absolute source path, token or remote credential. Registry/write API comes in 2A; this phase persists valid metadata in tests only.
3. `scan_runs`: UUID PK, project FK, snapshot association FK enforcing same project, profile ID/digest, checked scan status, created/started/completed timestamps. Initial status enum is queued/running/succeeded/partial/failed. No public operation can enqueue or mutate scan lifecycle yet. Phase 2A will add durable acceptance/jobs and lifecycle transitions before scan POST exists.
4. `audit_events`: UUID PK, bounded event/object types and object ID, trusted actor/component, safe request correlation, created_at, bounded allowlisted JSON metadata. Initial production event is project creation, committed with its project. Job fields/events are added in 2A.

Implement FK and essential enum/non-negative/identity constraints in PostgreSQL, not only Pydantic. Initial index: project scan history `(project_id, created_at DESC, id DESC)`. Do not create speculative findings, jobs, reviews, consent, runner or SOC tables. No automatic seed snapshots/scans/findings or invented scan results.

Storage integration fixtures create valid project/snapshot/scan metadata without filesystem intake. Prove read/persistence behavior with test-only factories, clearly distinct from a working scan pipeline. Project creation provides a real user-facing persisted write in Phase 1.

## API surface

| Route | Required behavior |
|---|---|
| `GET /health` | Public coarse 200 process liveness, no DB probe or configuration details |
| `GET /ready` | Public coarse 200 if DB reachable and at expected migration revision; otherwise 503 safe unavailable category |
| `POST /api/v1/projects` | Authenticated bounded `{name}`; 201 `{id,name,created_at}`; transaction inserts project and audit event together |
| `GET /api/v1/projects/{id}` | Authenticated 200 metadata or 404 |
| `GET /api/v1/scan-runs/{id}` | Authenticated read-only persisted `{id,project_id,snapshot_id,profile_id,profile_digest,status,created_at,started_at,completed_at}`; 404 unknown; no fake stages/results |

No scan submit, snapshot registration, list/history cursor, finding, triage, review, export or launcher route is implemented in Phase 1. They are introduced at their assigned phases. Protect interactive docs/OpenAPI with the same local access policy or disable interactive docs by default and export the schema through tests; tests verify the actual supported contract.

Return 401 for missing/invalid bearer, 403 denied Origin, 404 missing object, 422 typed validation, 413 oversized body, 503 dependency/schema unavailable and sanitized 500 for unexpected failures. Host rejection may be a documented 400. Add future conflict/capacity semantics only when their operations exist.

Error envelope: `{code,message,request_id,retryable,details}`. Validation details expose field locations and safe error codes only; no submitted values, request body, Pydantic input echo, stack trace, source, token or database connection string. Reject unknown write fields to prevent accidental credential/path ingestion. Set initial explicit budgets: project name 1–200 characters after normalization, project request body at most 16 KiB, bearer header at most 4 KiB, accepted request ID at most 64 safe ASCII characters. Enforce streamed body size, not Content-Length alone. Limits are configurable with safe bounded defaults and tests.

## Settings, access and session lifecycle

- Python runtime pinned within 3.12; choose/document a supported PostgreSQL major and immutable tested image digest. Record Docker Desktop/Linux-container prerequisites without claiming a successful check before it runs.
- Required DB URL and independently supplied high-entropy local API bearer secret; no committed/generated default credential. Secret values are excluded from representations and exception/log output. `.env.example` leaves them blank/non-secret. Tests inject synthetic secrets.
- Exact allowed Host values and browser Origin scheme/host/port tuples. Host header protection must work with local Compose routing. API may listen on `0.0.0.0` inside its container, but host publication is `127.0.0.1` only.
- Reject Origin `null` and non-allowlisted origins. Missing Origin is permitted for CLI/non-browser clients but never bypasses bearer auth. CORS allows only explicit origins/methods/headers; no cookies or wildcard credentials. Preflight may be answered without bearer only for approved origins; it returns no application data.
- Compare bearer secrets safely; do not use them as log/audit identity. Local reviewer/operator identity is application-controlled. No username/password UI, tenancy, sessions service or RBAC.
- One synchronous SQLAlchemy session per request/operation. Explicit commit/rollback ownership; close on all paths. No blocking DB work directly inside async event-loop handlers. Engine creation does not open connections during import.
- Allowlisted logs: event code, request ID, method, route template/status, duration and safe object IDs. Exclude raw URL queries, request/response bodies, full validation/DB exceptions, auth headers, project names and raw settings. Sanitize control characters. Accept a safe bounded request ID or generate one and return it in the response header.
- DB/schema readiness uses a bounded query/timeout. DB unavailability must not make `/health` fail or emit connection secrets. No dependency probes for future scanner/provider capabilities.

## Local execution and migration contract

Compose has `api` and `db` services, plus profile `test` with a dev-dependency `tests` image and separate disposable `test-db`. No Docker socket mounts. DBs have no host-published ports. API is non-root and publishes loopback only. DB/spool/home/credential directories are not broadly mounted into the API image; no spool exists until 2A. Build context excludes `.git`, `.env`, caches, local outputs and private files.

Migration is a one-shot operator command, not an automatic API startup action. A missing/outdated schema causes readiness 503. Initial downgrade is destructive and may be rehearsed only on explicitly disposable test data. Normal stop/restart preserves the volume. Never use `down -v`, recursive deletion or a schema reset as a routine recovery instruction.

The following are proposed future commands once implementation, dependency installation and project-scoped service execution are explicitly authorized. Implement the stated service/image names so these commands are reproducible; do not execute them during Phase 0:

```text
uv sync --frozen
uv run ruff check .
uv run mypy src
uv run pytest -m unit
uv run pytest -m api

docker compose config --quiet
docker compose build api
docker compose up -d db
docker compose run --rm api uv run --no-sync alembic upgrade head
docker compose up -d api

docker compose --profile test build tests
docker compose --profile test up -d test-db
docker compose --profile test run --rm tests uv run --no-sync pytest -m postgres
```

Initial lock creation precedes frozen installs and is recorded separately. Runtime image already includes its dependencies; `--no-sync` migration/runtime commands must not download packages. Configure the integration container's test URL separately from the API DB URL. Any raw Compose config rendering must not expose resolved secrets; `config --quiet` validates without printing it.

## Test strategy and completion criteria (G1)

| Check | Test requirement |
|---|---|
| Unit/config | Required/invalid settings, hidden secret representations, safe IDs/enums and request limits; no DB/network needed |
| API | Correct statuses/schema for all five routes; missing/wrong bearer; allowed/denied/null Origin; missing Origin with auth; Host rejection; safe preflight; absent future routes |
| Sanitization | Synthetic secrets placed in headers, invalid bodies and simulated DB/settings exceptions never appear in responses, application/server logs or audit fields |
| Session/transaction | Successful project plus audit commit; induced audit/storage failure rolls both back; session closes/rolls back on error |
| PostgreSQL | Real migrated DB, FK/enum/count constraints, valid snapshot/scan test factories, project write/query and read-only scan API |
| Migration | Empty DB to head; repeated upgrade head; expected-revision readiness; disposable base downgrade then head; never developer DB teardown |
| Restart | Create project through authenticated API, restart API and DB separately without deleting volume, retrieve same ID; test-only scan metadata also persists |
| Networking/build | Non-root API, loopback published port, DB unexposed, no daemon/home/secret build mounts, `.env` excluded; locked build reproducible |
| CI | Ruff, mypy, unit/API and real PostgreSQL migration/integration jobs declared with minimal permissions; no target scripts/provider keys/remote writes |

Register unit/api/postgres pytest markers with strict marker validation. Every existing Phase 1 test must be selected by at least one required CI command. Unit/API tests can use dependency fakes; DB behavior cannot be certified by mocks/SQLite. Test runner requires an explicit test URL and disposable-test identity before migration downgrade/cleanup. Missing PostgreSQL is a blocked/failing required check, not a green skip. Never auto-detect an ordinary development database as a test target.

The restart test/procedure must exercise actual processes/services, not just reopen an ORM session. Record executed commands, versions and evidence with redacted outputs. A missing service/network permission or runtime prevents a complete G1 claim until resolved. Check success/failure paths, not just app startup.

## Rollback and final report

Stop API and preserve DB volume/data. Keep schema/application compatibility documented. Rehearse initial downgrade/re-upgrade only on disposable test DB; for retained data prefer backup and forward correction. No rollback instruction authorizes unscoped Docker cleanup, repository reset or developer-data deletion.

Report exact changed files, dependency/image versions, migration revision, commands/results and pass/fail/skip counts, restart/network/log evidence, remaining limitations and rollback procedure. State which checks were blocked and why. No known high-severity Phase 1 defect may be hidden behind a passing unit suite. Stop after Phase 1 and supply a Phase 2A handoff; do not implement workers or claim the scanning MVP exists.

## Remaining Phase 1 blockers

No unresolved architectural decision blocks this specification. Explicit Phase 1 authorization is required. Compatible dependency resolution and executable PostgreSQL/Compose environment remain untested prerequisites to G1 completion. Scanner containment, queue recovery, provider vendor/privacy selection and UI work are later gates, not reasons to broaden Phase 1.
