# Phase 3 local operation and rollback

Use the existing Windows/NTFS workspace, Python 3.12/uv and Docker Desktop Linux engine.
Development project remains `asp-phase1-dev`; disposable PostgreSQL remains
`asp-phase1-test`. Preserve all retained volumes, source snapshots, scanner assets,
images and accepted earlier-phase evidence. No remote workflow activation is needed.

## Setup and forward migration

```powershell
uv sync --frozen
docker --context desktop-linux version
uv run python scripts/phase3_migrate.py
```

The migration helper requires real scanner and hosted admission disabled. It verifies
the exact project/database identity, stops only API/scan/triage workers, writes a private
custom-format backup, upgrades revision 0003 to 0004, compares retained counts/content
digests and restarts local services. Its recorded execution already completed; do not
rerun solely to overwrite the initial migration evidence. No downgrade of retained
development data is permitted. Fresh databases use the established explicit
`alembic upgrade head` after building application images and initializing the spool.

For an already migrated database:

```powershell
docker compose -p asp-phase1-dev --profile workers --profile triage build api worker triage-worker
docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait api worker triage-worker
```

API stays loopback-only at port 18081; DB/workers publish no ports. Triage worker has
UID/GID 10001, read-only root/source, dropped capabilities, no-new-privileges and the
existing 256 MiB/1 CPU/64 PID limits. It has no Docker client/socket or hosted key.
Snapshot evidence must be read through the Linux read-only spool mount; there is no
unsafe host-worker fallback for Windows source reads.

## API workflow

Use the existing authenticated local API transport. Submit
`POST /api/v1/findings/FINDING_UUID/triage` with body `{}` and a unique
`Idempotency-Key`. Default provider is `deterministic-v1`. Poll the returned Location;
inspect assessment/abstention, citations, coverage and independent scan status.
Do not interpret successful job publication as a confirmed vulnerability or fix.

For human review, GET the current review, then PUT its expected revision with an
approved disposition and optional explanation. Re-fetch on 409 and consciously review
the changed state rather than overwriting it. Structured feedback is optional, requires
a matching successful triage ID and never rewrites that AI outcome. Revision history
is immutable; earlier notes remain part of local history even after a new review.
Generated live validation revisions are labelled controlled validation, not a human
security verdict. No review UI or full developer CLI was added.

## Hosted adapter remains disabled

No actual external model request, paid use or source transmission is authorized by the
Phase 3 handoff. The adapter has been tested with mocked transport only. Do not enable
live hosted tests by following a setup example from another phase.

A separately authorized future live test would require approved synthetic inputs,
trusted opt-in settings, explicit matching consent and a key injected **only into the
triage provider process**. Keep provider configuration in ignored private storage such
as `.local/provider.env`, separate from the general `.env`; do not put a provider key
in the launcher/API/scanner-worker environment, build context or command line. The base
Compose file intentionally supplies no key. An operator would need a reviewed local
override for that provider-only injection; no live override/key was created here.

Before every send/retry, the worker reserves from the operation's persisted allowance
under current lease/consent locks. Revocation stops future reservations, not in-flight
requests or prior transmission. Source/config changes require new scoped consent.
Redaction is heuristic; approved source acquisition is not consent to external disclosure.
`store:false` is not a provider zero-retention agreement. Recheck model availability,
current terms/pricing and configuration version before any separately approved live use.

## Reproduce acceptance

```powershell
uv lock --check
uv sync --frozen
uv run ruff check .
uv run ruff format --check src runner scripts tests migrations
uv run mypy src
uv run python scripts/validate_phase3_tests.py
uv run python -m pytest -m "unit or api" --basetemp .cache/phase3-native-validation
uv run python -m tests.native_windows_snapshots --phase3
uv run python -m runner.validate_isolation --phase3
uv run python -m runner.validate_scanners --phase3
uv run python scripts/validate_phase3_live.py
uv run python scripts/validate_phase3_state.py
docker compose -p asp-phase1-test --profile test stop test-db
```

Use a fresh native basetemp path. Windows symlink fixture creation needs an administrator
shell or Developer Mode; blocked checks are not skips/passes. The operator supplied a
successful administrator run for the recorded 10-check Phase 3 NTFS proof.

The PostgreSQL harness uses a separate guarded database, records every original 25
scanner crash experiment plus five triage crash/transaction cases, and runs separate
processes for worker claims, acceptance/review races and blocked-provider recovery.
All hosted tests use explicit mock transports. Existing read-only CI automatically
includes these tests through its unit/API/PostgreSQL groups; it is not activated here.

Docker isolation/scanner harnesses must run sequentially with no host launcher active.
Their `--phase3` outputs preserve earlier accepted G4/G5 reports. Scanner images/DB are
reused by immutable identity; this phase does not require enabling scanner admission.
The live triage harness uses retained genuine controlled G5 findings, creates labelled
triage/review validation records, restarts only this project's services and proves scan
content remains unchanged. These records are retained rather than silently erased.

## Restart and safe rollback

```powershell
docker compose -p asp-phase1-dev --profile workers --profile triage restart triage-worker
```

Use this after a killed/stalled triage process once its cause is resolved and DB is
healthy. The new process recovers expired attempts or due retries without attaching to
old output. A provider thread that outlives its bound causes worker exit; do not leave
that process accepting additional work. Retry exhaustion is visible and does not fail
a completed scan. Retries may repeat external compute if future hosted calls are approved.

For rollback, set nonsecret `ASP_TRIAGE_ENABLED=false` in ignored `.env`, recreate API
and stop only `triage-worker`. Keep `ASP_HOSTED_ENABLED=false` and real scanner admission
disabled. Disabling acceptance does not delete or cancel already accepted operations.
Preserve jobs/attempts/outcomes/consents/review history and allow compatible forward fixes:

```powershell
docker compose -p asp-phase1-dev --profile triage stop triage-worker
docker compose -p asp-phase1-dev up -d --wait api
```

Current compatible code can still serve prior results and reviews while triage is
disabled. Ordinary scan workers remain isolated to scan jobs. Do not run old Phase 2B
code against revision 0004: its readiness/queue assumptions are incompatible. Development
downgrade is blocked; reversal tests require the exact disposable DB/user plus marker.
Never reset a repository, prune Docker, delete retained volumes or truncate real history.
The private backup is a preservation measure, not a claim of a full matched DB/spool
restore drill. Phase 7 owns expanded restore/retention work.
