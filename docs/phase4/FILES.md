# Phase 4 changed-file inventory

**8 modified files; 63 created files.** All changes belong to evaluation,
tests, test-image/context/line-ending configuration, separate evidence selectors or docs.
No application source, scanner policy/registry, launcher boundary, queue implementation,
database migration, runtime Compose configuration, dependency lock or existing accepted
Phase 0–3 report changed. Nothing is staged or committed.

Ignored credentials, private evaluation spools, temporary fixture copies, the original
retained-data baseline and check logs are local validation state, not deliverables.
Local instructions are unchanged and excluded from this inventory and build artifacts.

## Modified files

| File | Purpose |
| --- | --- |
| [.dockerignore](../../.dockerignore) | Allow only the versioned evaluation subtree in the local test build context; existing private-file denials remain. |
| [.gitattributes](../../.gitattributes) | Preserve exact frozen evaluation bytes across platform checkouts with LF text policy. |
| [Dockerfile](../../Dockerfile) | COPY evaluation only into the tests stage; no runtime application inclusion. |
| [README.md](../../README.md) | Link G7 results, honest limitations and Phase 5 authorization boundary. |
| [pyproject.toml](../../pyproject.toml) | Register evaluation tests and exclude inert fixture code from lint/format rewriting. |
| [runner/validate_isolation.py](../../runner/validate_isolation.py) | Select separate Phase 4 isolation evidence without changing the boundary. |
| [runner/validate_scanners.py](../../runner/validate_scanners.py) | Select separate Phase 4 scanner evidence without overwriting accepted reports. |
| [tests/native_windows_snapshots.py](../../tests/native_windows_snapshots.py) | Select separate Phase 4 native NTFS evidence. |

## Created files

| File | Purpose |
| --- | --- |
| [docs/phase4/COMMANDS.md](../../docs/phase4/COMMANDS.md) | Executed commands, corrected failures and safe diagnostic reruns. |
| [docs/phase4/COMPLETION-REPORT.md](../../docs/phase4/COMPLETION-REPORT.md) | Complete checkpoint/G7 status, results, versions, risks and next handoff. |
| [docs/phase4/EVALUATION-SUMMARY.md](../../docs/phase4/EVALUATION-SUMMARY.md) | Readable scanner/triage denominators and adversarial case-by-case results. |
| [docs/phase4/FILES.md](../../docs/phase4/FILES.md) | Complete file inventory with purpose. |
| [docs/phase4/RUNBOOK.md](../../docs/phase4/RUNBOOK.md) | Setup, reproduction, private preservation evidence and safe restart/rollback. |
| [docs/phase4/isolation-regression.json](../../docs/phase4/isolation-regression.json) | 31 actual controlled-container isolation checks. |
| [docs/phase4/persistence-evidence.json](../../docs/phase4/persistence-evidence.json) | 10 actual API/worker/DB restart, access, logging and retained-history checks; no application record writes. |
| [docs/phase4/runtime-evidence.json](../../docs/phase4/runtime-evidence.json) | 32 final runtime/preservation checks and exact versions. |
| [docs/phase4/scanner-regression.json](../../docs/phase4/scanner-regression.json) | 16 genuine-scanner regression checks. |
| [docs/phase4/test-evidence.json](../../docs/phase4/test-evidence.json) | 226-test results plus 25 scan/five triage crash trials. |
| [docs/phase4/triage-adversarial-evidence.json](../../docs/phase4/triage-adversarial-evidence.json) | Repeated real triage and scripted-adversarial outcomes, per-category metrics and agent identities. |
| [docs/phase4/windows-filesystem-evidence.json](../../docs/phase4/windows-filesystem-evidence.json) | 10 operator-administrator NTFS snapshot checks. |
| [evaluation/README.md](../../evaluation/README.md) | Label methodology, denominator rules, confidentiality, limitations and execution. |
| [evaluation/__init__.py](../../evaluation/__init__.py) | Trusted benchmark package boundary. |
| [evaluation/adversarial.json](../../evaluation/adversarial.json) | Sixteen versioned distinct attack goals and expected enforcement behavior. |
| [evaluation/adversarial.py](../../evaluation/adversarial.py) | Scripted production-boundary attacks, repeated offline; no live hosted execution. |
| [evaluation/attest.py](../../evaluation/attest.py) | Verify preserved actual scanner source bytes and attach identity metadata only. |
| [evaluation/corpus.py](../../evaluation/corpus.py) | Validate the freeze, materialize source bytes and compute eligible scanner metrics. |
| [evaluation/errata-v1.json](../../evaluation/errata-v1.json) | Preserve and disclose two invalid rule bindings; exclude them from formal metrics. |
| [evaluation/fixtures/authorization-negative/app.py](../../evaluation/fixtures/authorization-negative/app.py) | Frozen inert authorization-negative repository source/configuration; never executed. |
| [evaluation/fixtures/authorization-positive/app.py](../../evaluation/fixtures/authorization-positive/app.py) | Frozen inert authorization-positive repository source/configuration; never executed. |
| [evaluation/fixtures/ci-permissions-negative/.github/workflows/check.yml](../../evaluation/fixtures/ci-permissions-negative/.github/workflows/check.yml) | Frozen inert ci-permissions-negative repository source/configuration; never executed. |
| [evaluation/fixtures/ci-permissions-positive/.github/workflows/check.yml](../../evaluation/fixtures/ci-permissions-positive/.github/workflows/check.yml) | Frozen inert ci-permissions-positive repository source/configuration; never executed. |
| [evaluation/fixtures/deserialization-path-negative/app.py](../../evaluation/fixtures/deserialization-path-negative/app.py) | Frozen inert deserialization-path-negative repository source/configuration; never executed. |
| [evaluation/fixtures/deserialization-path-positive/app.py](../../evaluation/fixtures/deserialization-path-positive/app.py) | Frozen inert deserialization-path-positive repository source/configuration; never executed. |
| [evaluation/fixtures/docker-root-negative/Dockerfile](../../evaluation/fixtures/docker-root-negative/Dockerfile) | Frozen inert docker-root-negative repository source/configuration; never executed. |
| [evaluation/fixtures/docker-root-positive/Dockerfile](../../evaluation/fixtures/docker-root-positive/Dockerfile) | Frozen inert docker-root-positive repository source/configuration; never executed. |
| [evaluation/fixtures/javascript-dependency-negative/package-lock.json](../../evaluation/fixtures/javascript-dependency-negative/package-lock.json) | Frozen inert javascript-dependency-negative repository source/configuration; never executed. |
| [evaluation/fixtures/javascript-dependency-negative/package.json](../../evaluation/fixtures/javascript-dependency-negative/package.json) | Frozen inert javascript-dependency-negative repository source/configuration; never executed. |
| [evaluation/fixtures/javascript-dependency-positive/package-lock.json](../../evaluation/fixtures/javascript-dependency-positive/package-lock.json) | Frozen inert javascript-dependency-positive repository source/configuration; never executed. |
| [evaluation/fixtures/javascript-dependency-positive/package.json](../../evaluation/fixtures/javascript-dependency-positive/package.json) | Frozen inert javascript-dependency-positive repository source/configuration; never executed. |
| [evaluation/fixtures/javascript-shell-negative/app.js](../../evaluation/fixtures/javascript-shell-negative/app.js) | Frozen inert javascript-shell-negative repository source/configuration; never executed. |
| [evaluation/fixtures/javascript-shell-positive/app.js](../../evaluation/fixtures/javascript-shell-positive/app.js) | Frozen inert javascript-shell-positive repository source/configuration; never executed. |
| [evaluation/fixtures/javascript-sql-negative/app.js](../../evaluation/fixtures/javascript-sql-negative/app.js) | Frozen inert javascript-sql-negative repository source/configuration; never executed. |
| [evaluation/fixtures/javascript-sql-positive/app.js](../../evaluation/fixtures/javascript-sql-positive/app.js) | Frozen inert javascript-sql-positive repository source/configuration; never executed. |
| [evaluation/fixtures/kubernetes-privilege-negative/pod.yaml](../../evaluation/fixtures/kubernetes-privilege-negative/pod.yaml) | Frozen inert kubernetes-privilege-negative repository source/configuration; never executed. |
| [evaluation/fixtures/kubernetes-privilege-positive/pod.yaml](../../evaluation/fixtures/kubernetes-privilege-positive/pod.yaml) | Frozen inert kubernetes-privilege-positive repository source/configuration; never executed. |
| [evaluation/fixtures/python-dependency-negative/requirements.txt](../../evaluation/fixtures/python-dependency-negative/requirements.txt) | Frozen inert python-dependency-negative repository source/configuration; never executed. |
| [evaluation/fixtures/python-dependency-positive/requirements.txt](../../evaluation/fixtures/python-dependency-positive/requirements.txt) | Frozen inert python-dependency-positive repository source/configuration; never executed. |
| [evaluation/fixtures/python-eval-negative/app.py](../../evaluation/fixtures/python-eval-negative/app.py) | Frozen inert python-eval-negative repository source/configuration; never executed. |
| [evaluation/fixtures/python-eval-positive/app.py](../../evaluation/fixtures/python-eval-positive/app.py) | Frozen inert python-eval-positive repository source/configuration; never executed. |
| [evaluation/fixtures/python-shell-negative/app.py](../../evaluation/fixtures/python-shell-negative/app.py) | Frozen inert python-shell-negative repository source/configuration; never executed. |
| [evaluation/fixtures/python-shell-positive/app.py](../../evaluation/fixtures/python-shell-positive/app.py) | Frozen inert python-shell-positive repository source/configuration; never executed. |
| [evaluation/fixtures/python-sql-negative/app.py](../../evaluation/fixtures/python-sql-negative/app.py) | Frozen inert python-sql-negative repository source/configuration; never executed. |
| [evaluation/fixtures/python-sql-positive/app.py](../../evaluation/fixtures/python-sql-positive/app.py) | Frozen inert python-sql-positive repository source/configuration; never executed. |
| [evaluation/fixtures/secret-negative/credentials.txt](../../evaluation/fixtures/secret-negative/credentials.txt) | Frozen inert secret-negative repository source/configuration; never executed. |
| [evaluation/fixtures/secret-positive/credentials.txt](../../evaluation/fixtures/secret-positive/credentials.txt) | Frozen inert secret-positive repository source/configuration; never executed. |
| [evaluation/fixtures/typescript-eval-negative/app.ts](../../evaluation/fixtures/typescript-eval-negative/app.ts) | Frozen inert typescript-eval-negative repository source/configuration; never executed. |
| [evaluation/fixtures/typescript-eval-positive/app.ts](../../evaluation/fixtures/typescript-eval-positive/app.ts) | Frozen inert typescript-eval-positive repository source/configuration; never executed. |
| [evaluation/frozen-v1.json](../../evaluation/frozen-v1.json) | Pre-observation hashes of labels, split, attacks and every fixture file. |
| [evaluation/grading.py](../../evaluation/grading.py) | Independent conservative claim, source-range and remediation rubric. |
| [evaluation/manifest.json](../../evaluation/manifest.json) | 28 repository labels, rationale, provenance, evidence and fixed split. |
| [evaluation/report.py](../../evaluation/report.py) | Partition/category triage metrics and deterministic equivalence. |
| [evaluation/results/report.json](../../evaluation/results/report.json) | Combined machine-readable G7 quality/safety/gate report and artifact hashes. |
| [evaluation/results/scanner-observations.json](../../evaluation/results/scanner-observations.json) | Two genuine scanner repetitions with normalized metadata, source identity, timings and provenance. |
| [evaluation/runtime.py](../../evaluation/runtime.py) | Evaluation-only PostgreSQL replay through real scoped triage and review interfaces. |
| [evaluation/scan.py](../../evaluation/scan.py) | Trusted Windows host harness using fixed accepted offline scanner profiles. |
| [evaluation/summarize.py](../../evaluation/summarize.py) | Generate readable and machine reports from executed evidence. |
| [scripts/validate_phase4.py](../../scripts/validate_phase4.py) | Full regression runner and safe evaluation/crash-trial evidence extraction. |
| [scripts/validate_phase4_persistence.py](../../scripts/validate_phase4_persistence.py) | Verify existing resource reads and all retained rows across actual scoped service restarts and DB downtime. |
| [scripts/validate_phase4_state.py](../../scripts/validate_phase4_state.py) | Read-only runtime checks and exact retained-development-row equality evidence. |
| [tests/postgres/test_evaluation.py](../../tests/postgres/test_evaluation.py) | Real PostgreSQL benchmark and two adversarial repetitions, source identity and disclosure checks. |
| [tests/unit/test_evaluation_corpus.py](../../tests/unit/test_evaluation_corpus.py) | Frozen split/labels, denominator eligibility and independent prose-grading checks. |

