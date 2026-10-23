# Phase 4 executed command record

Commands run from `C:\Users\ridle\ai-security-platform`. Repeated iterative checks are
listed once. Secret-bearing command output and resolved Compose configuration were
never printed. No target script, target package installation, remote write, model call,
Git staging/commit/push, deployment or remote workflow activation occurred.

```powershell
git status --short
git diff --check
git diff --cached --quiet
git check-ignore --quiet AGENTS.md
uv lock --check
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check src runner scripts tests migrations evaluation
.\.venv\Scripts\mypy.exe src
.\.venv\Scripts\python.exe -m runner.validate_isolation --phase4
.\.venv\Scripts\python.exe -m runner.validate_scanners --phase4
.\.venv\Scripts\python.exe -m evaluation.scan
.\.venv\Scripts\python.exe -m evaluation.attest
.\.venv\Scripts\python.exe scripts/validate_phase4_state.py --record-before
.\.venv\Scripts\python.exe scripts/validate_phase4.py
.\.venv\Scripts\python.exe scripts/validate_phase4_persistence.py
.\.venv\Scripts\python.exe -m pytest -m "unit or api" --basetemp .cache/phase4-native-validation --tb=short
.\.venv\Scripts\python.exe -m pytest -m "unit or api" --basetemp .cache/phase4-native-final --tb=short
.\.venv\Scripts\python.exe -m tests.native_windows_snapshots --phase4
.\.venv\Scripts\python.exe scripts/validate_phase4_state.py
.\.venv\Scripts\python.exe -m evaluation.summarize
docker compose -p asp-phase1-test --profile test stop test-db
```

The full regression wrapper executes:

```powershell
docker compose -p asp-phase1-test --profile test build tests
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync ruff check .
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync mypy src
docker compose -p asp-phase1-test --profile test run --rm tests uv run --no-sync pytest -q -s -p no:cacheprovider
```

Initial evaluation scaffolding was generated once under ignored `.cache/` before any
corpus scanner observations. The checked-in versioned fixture files/manifests and freeze
are the deliverable, not a label-generating runtime step. Format checks exclude inert
fixture scripts so target source is neither imported nor rewritten by lint automation.

The first scanner attempt correctly stopped at the existing 32-snapshot spool quota
during repetition two. The harness was corrected to use independent bounded private
spools for each repetition; quotas, source labels and product behavior were unchanged.
The complete repeated benchmark was then rerun. Partial private spools were preserved.

All 56 actual snapshots were subsequently reverified against byte-identical materialized
source before PostgreSQL replay. Explicit secret-slot line endings prevent Windows/Linux
text-mode differences. This attached source digests without changing scanner results.
The Kubernetes annotation binding error is retained in a versioned errata file, with
both original cases ungraded rather than relabelled to improve metrics.
The first full regression reported 224 passed/one failed because a metric unit fixture
lacked its category field. The fixture was corrected without weakening validation;
the final full regression passed all 226 cases, including independent prose grading.

The first native pytest invocation under restricted sandbox identity encountered ACL
denials from tests that intentionally protect snapshots. Rerunning with the host account
permissions and a fresh scoped temporary directory passed the same tests. The two NTFS
symlink fixtures separately needed the operator's administrator command; the final
Phase 4 artifact records 10 passed with no blocked or skipped checks.

A state check run while benchmark containers were active correctly rejected the
`no_scanner_containers` assertion. The final check runs only after controlled scanning
finishes. These failed attempts are not counted as passing evidence or hidden skips.
Remaining failures, if any, are stated in the final completion report.

Read-only runtime validation queries only the named development project/database and
compares aggregate fingerprints. Scanner execution uses only existing pinned local
assets. Public real-scan admission and hosted transmission are never enabled. Package
resolution is checked with the unchanged lock; no additional dependency was required.
The persistence harness uses existing project/scan/finding/triage/review/history reads,
restarts only the four development services, verifies health/readiness with the actual
database down, restores it in a finally block and compares every retained table. It
creates no application records and inspects logs without printing credential values.
