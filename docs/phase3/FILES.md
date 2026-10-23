# Phase 3 changed files

20 existing files modified; 31 files created. No staged files or
commits. Ignored local credentials, private backups, build caches, validation logs and
the retained snapshot spool are not deliverables. Local instructions are unchanged and
excluded from images and this inventory. No accepted Phase 0/1/2A/2B documents, scanner
registry, scanner rules, dependency lock or launcher isolation implementation changed.

## Modified files

| File | Purpose |
| --- | --- |
| [README.md](../../README.md) | Link Phase 3 delivery, limits and the next authorization boundary. |
| [compose.yaml](../../compose.yaml) | Add the restricted separate triage worker and explicit disabled hosted defaults. |
| [pyproject.toml](../../pyproject.toml) | Register the initial agent test marker; dependency set and lock remain unchanged. |
| [runner/validate_isolation.py](../../runner/validate_isolation.py) | Write separate Phase 3 G4 evidence without changing the launcher boundary. |
| [runner/validate_scanners.py](../../runner/validate_scanners.py) | Write separate Phase 3 G5 evidence while preserving accepted reports. |
| [src/ai_security_platform/api/app.py](../../src/ai_security_platform/api/app.py) | Register the Phase 3 router and update the application title. |
| [src/ai_security_platform/api/routes/findings.py](../../src/ai_security_platform/api/routes/findings.py) | Expose separate assessment/review summaries. |
| [src/ai_security_platform/api/routes/scan_runs.py](../../src/ai_security_platform/api/routes/scan_runs.py) | Add optional review-disposition filtering without changing old cursors. |
| [src/ai_security_platform/api/security.py](../../src/ai_security_platform/api/security.py) | Permit narrowly scoped review PUT and consent DELETE preflight. |
| [src/ai_security_platform/config.py](../../src/ai_security_platform/config.py) | Typed triage admission and default-off hosted settings. |
| [src/ai_security_platform/jobs/controller.py](../../src/ai_security_platform/jobs/controller.py) | Discriminate scan and triage leases/claims/recovery. |
| [src/ai_security_platform/storage/base.py](../../src/ai_security_platform/storage/base.py) | Require the compatible Phase 3 migration revision. |
| [src/ai_security_platform/storage/intake.py](../../src/ai_security_platform/storage/intake.py) | Allow the fenced provider-reservation audit actor. |
| [src/ai_security_platform/storage/models.py](../../src/ai_security_platform/storage/models.py) | Add scoped triage/consent/outcome/reservation/review persistence constraints. |
| [tests/api/test_contracts.py](../../tests/api/test_contracts.py) | Preserve existing contracts and include new authorized routes. |
| [tests/native_windows_snapshots.py](../../tests/native_windows_snapshots.py) | Separate Phase 3 native filesystem evidence. |
| [tests/postgres/conftest.py](../../tests/postgres/conftest.py) | Guarded disposable cleanup of new tables and immutable history. |
| [tests/postgres/test_database.py](../../tests/postgres/test_database.py) | Validate new schema and safe migration lifecycle. |
| [tests/unit/test_infrastructure.py](../../tests/unit/test_infrastructure.py) | Assert the separate restricted triage service. |
| [tests/unit/test_settings.py](../../tests/unit/test_settings.py) | Check safe new configuration defaults. |

## Created files

| File | Purpose |
| --- | --- |
| [docs/phase3/ARCHITECTURE-AND-CONTRACTS.md](../../docs/phase3/ARCHITECTURE-AND-CONTRACTS.md) | Implementation boundaries, schema, API, budgets and confidentiality contract. |
| [docs/phase3/COMMANDS.md](../../docs/phase3/COMMANDS.md) | Executed command families and validation details. |
| [docs/phase3/COMPLETION-REPORT.md](../../docs/phase3/COMPLETION-REPORT.md) | Gate decisions, complete results, versions, limits and next handoff. |
| [docs/phase3/FILES.md](../../docs/phase3/FILES.md) | Complete changed-file inventory. |
| [docs/phase3/RUNBOOK.md](../../docs/phase3/RUNBOOK.md) | Reproduction, safe restart, compatible rollback and disabled hosted operation. |
| [docs/phase3/isolation-regression.json](../../docs/phase3/isolation-regression.json) | Actual 31-check controlled-container G4 rerun. |
| [docs/phase3/live-evidence.json](../../docs/phase3/live-evidence.json) | Actual 10-check API, persistence, privilege and confidentiality pipeline. |
| [docs/phase3/migration-evidence.json](../../docs/phase3/migration-evidence.json) | Forward revision, private backup metadata and retained counts/content. |
| [docs/phase3/runtime-evidence.json](../../docs/phase3/runtime-evidence.json) | 31 final runtime checks and exact installed versions. |
| [docs/phase3/scanner-regression.json](../../docs/phase3/scanner-regression.json) | Actual 16-check G5 rerun with genuine scanner outputs. |
| [docs/phase3/test-evidence.json](../../docs/phase3/test-evidence.json) | 222-test results and 25 scan/five triage crash experiments. |
| [docs/phase3/windows-filesystem-evidence.json](../../docs/phase3/windows-filesystem-evidence.json) | Operator-administered 10-check NTFS regression. |
| [migrations/versions/0004_triage_review.py](../../migrations/versions/0004_triage_review.py) | Forward-only retained-data extension; guarded disposable downgrade. |
| [policies/triage-rules.json](../../policies/triage-rules.json) | Frozen trusted rule definitions and original scanner-policy provenance. |
| [scripts/phase3_migrate.py](../../scripts/phase3_migrate.py) | Scoped private backup, forward migration and retained-row comparison. |
| [scripts/validate_phase3_live.py](../../scripts/validate_phase3_live.py) | Actual local API, review race, container restarts and scan independence proof. |
| [scripts/validate_phase3_state.py](../../scripts/validate_phase3_state.py) | Final privilege, network, schema, disclosure and Git state evidence. |
| [scripts/validate_phase3_tests.py](../../scripts/validate_phase3_tests.py) | Full real PostgreSQL regression and original/new crash-trial evidence. |
| [src/ai_security_platform/agent/__init__.py](../../src/ai_security_platform/agent/__init__.py) | Bounded investigation package. |
| [src/ai_security_platform/agent/contracts.py](../../src/ai_security_platform/agent/contracts.py) | Strict tool, evidence, assessment, consent and review schemas. |
| [src/ai_security_platform/agent/engine.py](../../src/ai_security_platform/agent/engine.py) | Explicit budgeted tool loop, citation validation and provider watchdog. |
| [src/ai_security_platform/agent/policy.py](../../src/ai_security_platform/agent/policy.py) | Versioned prompt, redaction, configuration identity and budgets. |
| [src/ai_security_platform/agent/providers.py](../../src/ai_security_platform/agent/providers.py) | Deterministic genuine investigation and fixed-endpoint optional hosted adapter. |
| [src/ai_security_platform/agent/rules.py](../../src/ai_security_platform/agent/rules.py) | Validate the trusted catalog against scanner provenance. |
| [src/ai_security_platform/agent/tools.py](../../src/ai_security_platform/agent/tools.py) | Read-only finding/source/rule/coverage/context with server-enforced scope. |
| [src/ai_security_platform/api/routes/triage.py](../../src/ai_security_platform/api/routes/triage.py) | Authenticated triage, consent and optimistic review/history APIs. |
| [src/ai_security_platform/jobs/triage.py](../../src/ai_security_platform/jobs/triage.py) | Durable triage claim, fenced publication/reservations and recovery. |
| [src/ai_security_platform/jobs/triage_worker.py](../../src/ai_security_platform/jobs/triage_worker.py) | Separate bounded provider/evidence worker with independent heartbeat. |
| [src/ai_security_platform/storage/triage.py](../../src/ai_security_platform/storage/triage.py) | Atomic idempotent acceptance, scoped consent and immutable human history. |
| [tests/postgres/test_triage.py](../../tests/postgres/test_triage.py) | Real DB/process investigation, review, confidentiality, consent and recovery checks. |
| [tests/unit/test_agent_boundaries.py](../../tests/unit/test_agent_boundaries.py) | Malformed/unauthorized tools, hosted wire shape, limits and sanitization checks. |

