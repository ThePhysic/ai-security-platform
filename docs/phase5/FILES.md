# Phase 5 file inventory

48 created and 12 modified reviewable repository files.
No prior phase documents, frozen evaluation/policy files, migrations, agent/scanner
behavior or local instructions were changed. No files were staged.

| File | Change | Purpose |
| --- | --- | --- |
| `.dockerignore` | Modified | Allow the named developer workflow in test context; retain all private-file denials. |
| `.gitattributes` | Modified | Preserve vendored JSON Schema/license bytes with LF. |
| `.github/workflows/ci.yml` | Modified | Restrict trusted foundation execution to manual default-branch dispatch. |
| `.github/workflows/developer-guardrails.yml` | Created | Pinned, least-privilege controlled artifact-only CI demonstration. |
| `Dockerfile` | Modified | Include the developer workflow definition in the test stage only. |
| `README.md` | Modified | Publish Phase 5 status and links; require separate Phase 6 authorization. |
| `docs/phase5/ARCHITECTURE-AND-CONTRACTS.md` | Created | Phase 5 implementation, validation, measurements, inventory or operating contract. |
| `docs/phase5/COMMANDS.md` | Created | Phase 5 implementation, validation, measurements, inventory or operating contract. |
| `docs/phase5/COMPLETION-REPORT.md` | Created | Phase 5 implementation, validation, measurements, inventory or operating contract. |
| `docs/phase5/FILES.md` | Created | Phase 5 implementation, validation, measurements, inventory or operating contract. |
| `docs/phase5/PERFORMANCE.md` | Created | Phase 5 implementation, validation, measurements, inventory or operating contract. |
| `docs/phase5/RUNBOOK.md` | Created | Phase 5 implementation, validation, measurements, inventory or operating contract. |
| `docs/phase5/VALIDATION.md` | Created | Phase 5 implementation, validation, measurements, inventory or operating contract. |
| `docs/phase5/acceptance.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/ci-evidence.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/cli-interruption-evidence.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/examples/guardrails.json` | Created | Sanitized schema-valid controlled CI example; no source excerpts or credentials. |
| `docs/phase5/examples/guardrails.sarif` | Created | Sanitized schema-valid controlled CI example; no source excerpts or credentials. |
| `docs/phase5/examples/policy.json` | Created | Sanitized schema-valid controlled CI example; no source excerpts or credentials. |
| `docs/phase5/final-runtime-update.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/frozen-provenance.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/hardware.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/isolation-regression.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/live-evidence.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/performance-evidence.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/recovery-evidence.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/regression-comparison.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/runtime-evidence.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/scanner-regression.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/test-evidence.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/triage-adversarial-evidence.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/windows-filesystem-evidence.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `docs/phase5/workload-provenance.json` | Created | Reproducible sanitized Phase 5 validation/provenance/acceptance evidence. |
| `pyproject.toml` | Modified | Add development-only JSON Schema validation and reliability test marker. |
| `runner/validate_isolation.py` | Modified | Independent Phase 5 evidence/private spool and correct orphan-child selector. |
| `runner/validate_scanners.py` | Modified | Independent Phase 5 real scanner regression evidence/private spool. |
| `scripts/generate_ci_artifacts.py` | Created | Generate validated offline artifacts from controlled retained real observations. |
| `scripts/validate_phase5.py` | Created | Run full real PostgreSQL/process regressions and extract safe workload/evaluation evidence. |
| `scripts/validate_phase5_ci.py` | Created | Clean candidate build, offline restricted artifact extraction and unit/API checks. |
| `scripts/validate_phase5_live.py` | Created | Actual CLI subprocesses, native intake, controlled real scans and restart/outage tests. |
| `scripts/validate_phase5_state.py` | Created | Read-only runtime, credential and retained-row preservation checks. |
| `src/ai_security_platform/api/routes/scan_runs.py` | Modified | Extend existing authenticated export with verified bounded JSON/SARIF. |
| `src/ai_security_platform/cli/main.py` | Modified | Add bounded developer commands, safe resource parsing, responses and exit handling. |
| `src/ai_security_platform/cli/workflow.py` | Created | Bounded wait/pagination, explicit policy loading and safe export orchestration. |
| `src/ai_security_platform/reporting/__init__.py` | Created | Reporting package. |
| `src/ai_security_platform/reporting/contracts.py` | Created | Versioned typed JSON report and scoped source-reference validation. |
| `src/ai_security_platform/reporting/core.py` | Created | Sanitized deterministic JSON/SARIF with source/provenance verification. |
| `src/ai_security_platform/reporting/files.py` | Created | Private, exclusive atomic scoped artifact publication. |
| `src/ai_security_platform/reporting/policy.py` | Created | Strict deterministic scanner-only policy and exit precedence. |
| `tests/native_windows_snapshots.py` | Modified | Independent Phase 5 native administrator evidence selector. |
| `tests/postgres/test_cli_process.py` | Created | Actual CLI timeout/SIGINT independent process proof. |
| `tests/postgres/test_performance.py` | Created | Real PostgreSQL 1/2/4-worker workload, plans, metrics and measured kill recovery. |
| `tests/postgres/test_reporting.py` | Created | Real persisted HTTP exports, schema/source scope, pagination and CLI protocol. |
| `tests/schemas/OASIS-LICENSE.md` | Created | Preserve upstream schema license/notice. |
| `tests/schemas/provenance.json` | Created | Official schema commit, URL and digest. |
| `tests/schemas/report-v1.json` | Created | Generated platform JSON report schema. |
| `tests/schemas/sarif-2.1.0.json` | Created | Official pinned OASIS SARIF validation schema. |
| `tests/unit/test_guardrails_workflow.py` | Created | Workflow security/static permissions and pinned offline schema checks. |
| `tests/unit/test_reporting_cli.py` | Created | Policy precedence, schema stability, disclosure, unsafe references and artifact/wait boundaries. |
| `uv.lock` | Modified | Lock the validator and its four transitive development dependencies. |

Ignored local outputs are intentionally excluded from reviewable/published artifacts:

- `.env`: only the real-scan admission toggle was temporarily enabled for controlled
  validation, then restored false. Existing credentials stayed private; no new credential
  was generated or printed.
- `.venv/`: locked project/development dependency installation, including JSON Schema validator.
- `.cache/phase5-*`: private clean candidate builds, logs, row-hash baseline, controlled
  fixtures and temporary native test directories. These can contain source or diagnostics;
  never publish them. Failed-attempt diagnostics were preserved privately.
- `.local/phase5-probes/` and `.local/phase5-fixtures/`: private controlled regression spools.
- `.local/snapshot-spool/`: three new retained controlled snapshots, preserving all accepted
  snapshots and existing quotas. No published source was deleted.
- `.local/reports/`: private diagnostic and genuine scanner exports; existing artifacts
  were not overwritten. Use the sanitized reviewable examples for review.

Project application/test images were rebuilt and scoped disposable containers created/
removed without pruning old images or volumes. The development database contains the
clearly named controlled validation records documented in runtime evidence. No unrelated
repository, container, network, volume or data was altered.
