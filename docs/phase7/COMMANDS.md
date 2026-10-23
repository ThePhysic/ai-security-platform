# Executed command ledger

All commands ran locally in the authorized workspace. Secrets were read privately from
ignored configuration. Subprocess failures were captured/sanitized; no resolved Compose
configuration, private dump, full snapshot or credential value was printed.

## Foundation and focused native validation

```powershell
uv lock --check
uv sync --frozen
uv lock
uv sync --frozen
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe src
.\.venv\Scripts\python.exe -m pytest tests/unit/test_snapshots.py -q --basetemp .cache/phase7-native-smoke-elevated
.\.venv\Scripts\python.exe -m pytest tests/unit/test_lifecycle.py tests/unit/test_reporting_cli.py -q --basetemp .cache/phase7-lifecycle-native-boundary-final
.\.venv\Scripts\python.exe -m tests.native_windows_snapshots --phase7
```

`uv lock` recorded the six exact/hash build constraints; all 46 existing project/runtime/dev
package versions stayed unchanged. No additional application runtime package was installed.
Public PyPI wheel metadata supplied the build hashes. The final native focused run passed
53 tests; the earlier snapshot-only run passed 25 (overlapping coverage). Administrator
NTFS evidence records ten passes, including the initially blocked symlink fixtures.

## Complete regressions and actual scanner boundary

```powershell
.\.venv\Scripts\python.exe scripts/validate_phase7.py
.\.venv\Scripts\python.exe -m runner.validate_isolation --phase7
.\.venv\Scripts\python.exe -m runner.validate_scanners --phase7
.\.venv\Scripts\python.exe -m scripts.validate_phase7_supply_chain
.\.venv\Scripts\python.exe scripts/validate_phase7_ci.py
```

The backend wrapper builds/runs `asp-phase1-test` with Ruff, mypy and
`uv run --no-sync pytest -q -s -p no:cacheprovider`; all destructive fixture/migration
operations are guarded to `asp_phase1_test` / `asp_test`. It captures the 25 scan and
five triage experiments, frozen evaluations and fixed workload/query-plan observations.
Raw logs remain `.cache/phase7-results/`. Scanner probes use separate Phase 7 spools;
31 containment and 16 genuine scanner checks passed. No policy/image/DB refresh occurred.

The supply-chain helper queried OSV using only 50 public package names/versions, resolved
official pinned action commits through GitHub's read-only API, and verified local scanner
image/database identities. One broad Trivy advisory match is retained and assessed in
[FINDINGS.md](FINDINGS.md). No private source or credentials were transmitted.

## Clean build and actual service startup

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_phase7_rebuild
.\.venv\Scripts\python.exe -m scripts.maintenance prepare-sandbox restore
.\.venv\Scripts\python.exe -m scripts.maintenance prepare-sandbox clean
docker --context desktop-linux compose --env-file .local/phase7-restore/environment.env -f compose.phase7.yaml -p asp-phase7-restore up -d --wait db
docker --context desktop-linux compose --env-file .local/phase7-clean/environment.env -f compose.phase7.yaml -p asp-phase7-clean up -d --wait db
docker --context desktop-linux compose --env-file .local/phase7-clean/environment.env -f compose.phase7.yaml -p asp-phase7-clean run --rm api uv run --no-sync alembic upgrade head
docker --context desktop-linux compose --env-file .local/phase7-clean/environment.env -f compose.phase7.yaml -p asp-phase7-clean up -d --wait --no-build api worker triage-worker
.\.venv\Scripts\python.exe -m scripts.validate_phase7_retention
```

The rebuild helper executes `docker --context desktop-linux build --no-cache --target runtime
--tag asp-phase7/platform:local .` from a new allowlisted context, followed by scoped
`npm.cmd ci --ignore-scripts --no-audit` and `npm.cmd run build`. Exact web hashes match.
Base images remain pinned/cached; no full image-byte reproducibility is claimed.

## Backup, restore and controlled demonstration

```powershell
.\.venv\Scripts\python.exe -m scripts.maintenance retention
.\.venv\Scripts\python.exe -m scripts.maintenance artifacts
.\.venv\Scripts\python.exe -m scripts.maintenance backup
.\.venv\Scripts\python.exe -m scripts.validate_phase7_restore
.\.venv\Scripts\python.exe -m scripts.validate_phase7_demo
```

Backup stdout was redirected to private UTF-8 receipt files under `.cache/`; contents were
not published. The first restore was interrupted after verified spool copy, resumed,
matched all 18 table fingerprints and reverified idempotently. The restore helper added
corruption/missing/mismatch, actual authenticated API/source checks and a real PostgreSQL
backend termination during transactional pg_restore, followed by successful retry.

The latest backup includes completed browser/demo history. A fresh generated 32-hex
restore instance was prepared, its own DB started, and that backup restored without
overwriting the initial drill. [Latest restore evidence](latest-restore-evidence.json)
records final checks. Parameterized key/digest/instance commands are in the
[recovery contract](RETENTION-AND-RECOVERY.md); actual receipts remain private.

The controlled demo uses the approved launcher/CLI/API/worker path, temporarily enables
only real local scanning, and disables admission in `finally`. Hosted admission is always
false. It performs an actual project-only API/DB restart, explicit human writes and
JSON/SARIF schema validation. All created application history is retained.

## Browser, final runtime and safe shutdown

```powershell
.\.venv\Scripts\python.exe scripts/validate_phase7_browser.py
.\.venv\Scripts\python.exe scripts/validate_phase7_assets.py
.\.venv\Scripts\python.exe scripts/validate_phase7_state.py
.\.venv\Scripts\python.exe -m scripts.validate_phase7_environments
git diff --check
docker compose -p asp-phase1-test --profile test stop test-db
```

The browser wrapper runs guarded preparation, locked npm install, strict TypeScript/Vite
build, existing project-local Chromium availability, 19 full cases and one compiled-preview
case from the clean context. It stops on a failed prerequisite. Its private logs redact
operator secrets; screenshots/video/traces remain disabled. The previously verified
project Vite process alone was stopped before tests; the final local UI was restarted.

Application images were built/recreated only under the existing `asp-phase1-dev` project.
Disposable clean/restore services were stopped after inspection; their volumes and spools
remain. No unscoped prune, retained-volume deletion, database reset, Git staging/commit/push,
remote workflow activation, public deployment, hosted call, Phase 8 or Matroid change ran.

## Corrected validation attempts

- Native filesystem tests needed an administrator symlink run; the eight-pass blocked
  report was superseded by ten actual passes, never counted as success beforehand.
- An ordinary sandbox pytest invocation could not access its private NTFS fixture directory;
  the scoped authorized native run succeeded.
- Initial restore assertions incorrectly expected unavailable/503. Existing contracts are
  a succeeded outcome containing source-unavailable abstention and a 409 source-invalid
  export. Assertions were corrected after reading the implementation; no API changed.
- Extended Windows path fixture creation hit the host path limit. The test now explicitly
  exercises rejection of that unsupported namespace; Linux validates the full portable path.
- Native DirEntry stat omitted reliable hardlink counts; artifact inspection uses lstat.
  The internal publication lock is accounted for while retaining the no-partial-artifact
  and FileExistsError/no-overwrite contracts.
- Ruff caught long strings in new host validators; they were corrected and affected
  builds/static/full checks rerun. Initial failures are not passing acceptance evidence.

The final review caught disposable Compose environment inheritance of the launcher
capability. It was cleared for both workers, tested statically and in actual containers,
and rerun through full PostgreSQL/clean-CI/native/environment validation. The previous
285-test/175-CI-test/52-native review is archived in `review-1/`, not rewritten as final
evidence. The test Docker context now explicitly includes the nonsecret Phase 7 template.
