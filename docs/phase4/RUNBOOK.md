# Phase 4 evaluation runbook

Phase 4 evaluates the existing local AppSec product. Runtime application code, scanner
policy, migrations, hosted defaults and immutable human-review history are unchanged.
Use Windows with the established Python 3.12/uv environment and Docker Desktop Linux
containers. Project namespaces remain `asp-phase1-dev` and `asp-phase1-test`.

## Reproduce the benchmark

Preserve prior evidence. Stop any active host launcher before controlled Docker checks.
Do not enable public scanner admission or hosted execution. The accepted scanner images,
rule catalog, offline vulnerability DB and G4 proof must be available and valid. An
unavailable/stale DB or isolation mismatch blocks execution; no network download or
host-scanner fallback occurs. Asset preparation/refresh is a separate trusted operation
following the Phase 2B runbook, not a reason to change v1 labels or silently repin results.

```powershell
uv lock --check
uv sync --frozen
uv run ruff check .
uv run ruff format --check src runner scripts tests migrations evaluation
uv run mypy src
uv run python -m runner.validate_isolation --phase4
uv run python -m runner.validate_scanners --phase4
uv run python -m evaluation.scan
uv run python scripts/validate_phase4.py
uv run python scripts/validate_phase4_persistence.py
uv run python -m pytest -m "unit or api" --basetemp .cache/phase4-native-new-run
uv run python -m tests.native_windows_snapshots --phase4
uv run python scripts/validate_phase4_state.py
uv run python -m evaluation.summarize
docker compose -p asp-phase1-test --profile test stop test-db
```

Execute each command only after its predecessor succeeds. Required checks fail/block,
never silently skip. Native snapshot tests require the real host account's ACL access;
the two native symlink cases additionally need Developer Mode or an administrator shell.
Use a fresh native basetemp directory. The operator's recorded Phase 4 administrator run
passed all 10 checks. Do not overwrite it with an ordinary run unable to create symlinks.

The state check must run **after** scanner validation/evaluation finishes because it
requires zero active scanner containers. The corpus scanner uses an exclusive launcher
lock and separate private per-run/per-repetition spools. Never run scanner harnesses
concurrently with one another or a production host launcher. Public real-scan admission
stays disabled throughout; tests use the accepted fixed-profile boundary directly on
controlled synthetic inputs.
The persistence harness briefly restarts only this development project's API/workers/DB,
checks actual unavailable-DB readiness, and reads existing resources before/after. It
does not create application records; a finally block restores the database. Run it when
the local operator is not performing concurrent writes, so equality checks remain meaningful.

`validate_phase4.py` builds the test image, runs Ruff, mypy and the complete pytest suite,
including the frozen benchmark and real PostgreSQL/process regressions. It parses a safe
line-delimited evaluation result from container stdout. No writable host result mount
or Docker authority enters the test/application containers. The test image alone includes
the corpus; application runtime images do not COPY it. Missing genuine scanner observations
make the benchmark fail explicitly rather than substitute fake findings.

The full suite writes only the exact guarded disposable PostgreSQL database. It replays
genuine normalized output into evaluation metadata, reacquires/verifies source in Linux,
uses real triage jobs/tools/fencing/publication and writes label-derived review revisions
there. No retained development review history is modified. Fixture package manifests,
Dockerfiles, CI YAML, Python and JavaScript/TypeScript remain inert data.

The first recorded scanner runs predated the source-identity report fields. A one-time
`uv run python -m evaluation.attest` verified all 56 preserved actual source snapshots,
matched their bytes to materialization, and attached only content/manifest digests to
observations. Future `evaluation.scan` runs record these identities directly. The secret
slot uses explicit CRLF bytes on both Windows and Linux, preserving the actual Windows
input instead of allowing implicit text-mode newline differences. No scanner finding,
source label or scanned byte was changed by attestation.

## Preservation evidence and outputs

For the original validation, `validate_phase4_state.py --record-before` recorded private
aggregate row fingerprints in `.cache/phase4-retained-before.json` before PostgreSQL
evaluation. It intentionally refuses to overwrite the first baseline. The final state
check compares all 17 development tables and records counts/content hashes only, never
rows or credentials. MD5 here is an equality observation, not tamper-proofing or a change
to SHA256 snapshot identities. A future operator should retain the original baseline
and explicitly manage a distinct validation record if legitimate development data changes.

- `evaluation/manifest.json`, `adversarial.json`, `frozen-v1.json`: immutable v1 labels,
  input hashes, split and attack expectations.
- `evaluation/results/scanner-observations.json`: two genuine offline scanner repetitions,
  bounded normalized findings, coverage, versions, timings and baseline denominators.
- `docs/phase4/triage-adversarial-evidence.json`: two deterministic and scripted-attack
  repetitions, triage metrics, review proxy and agent version identities.
- `evaluation/results/report.json`: combined machine-readable gate/quality/safety report.
- `docs/phase4/EVALUATION-SUMMARY.md`: readable results, denominators and case table.
- Separate Phase 4 isolation, scanner, NTFS, runtime and regression JSON reports preserve
  all earlier accepted artifacts. Ignored `.cache/phase4-results/` contains check logs.

Reported durations are actual local observations and vary. Tokens are conservative
reservations, cost/peak memory are unmeasured. Hosted adapter probes use mocked transport;
actual hosted model quality and paid use remain unverified and unauthorized.

## Restart and rollback

Normal development services require no Phase 4 migration or rebuild. If stopped, use
the compatible Phase 3 command:

```powershell
docker compose -p asp-phase1-dev --profile workers --profile triage up -d --wait api worker triage-worker
```

Keep hosted and real scanning disabled. Preserve database revision `0004_triage_review`,
all retained volumes, snapshots, images/assets and review history. Stop only the disposable
test database using the command above after validation; its volume is retained.

Evaluation rollback means stop running the harness and retain the versioned corpus and
observations for diagnosis. No production schema/provider change needs reversal. A failed
provider/policy evaluation does not justify changing held-out labels or dropping history.
Use an explicitly versioned future experiment and compare against v1. Do not reset Git,
prune Docker, delete old snapshots, downgrade retained data or run `down -v`.

Phase 5 implementation, full CLI/SARIF/developer integration, load engineering, UI,
remediation, hosted calls and SOC work are not authorized by this phase.
