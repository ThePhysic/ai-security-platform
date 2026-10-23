# Phase 2A file inventory

Tracked project files only; ignored credentials, backups, spool, caches and virtualenv are excluded.

## Modified

- .dockerignore
- .github/workflows/ci.yml
- .gitignore
- README.md
- compose.yaml
- pyproject.toml
- src/ai_security_platform/api/app.py
- src/ai_security_platform/api/routes/scan_runs.py
- src/ai_security_platform/api/security.py
- src/ai_security_platform/config.py
- src/ai_security_platform/domain/scans.py
- src/ai_security_platform/storage/base.py
- src/ai_security_platform/storage/models.py
- tests/api/test_contracts.py
- tests/postgres/conftest.py
- tests/postgres/test_database.py
- tests/unit/test_infrastructure.py
- tests/unit/test_settings.py

## Created

- docs/phase2a/API-AND-SCHEMA.md
- docs/phase2a/COMMANDS.md
- docs/phase2a/COMPLETION-REPORT.md
- docs/phase2a/FILES.md
- docs/phase2a/RUNBOOK.md
- docs/phase2a/live-evidence.json
- docs/phase2a/migration-evidence.json
- docs/phase2a/runtime-evidence.json
- docs/phase2a/test-evidence.json
- docs/phase2a/windows-filesystem-evidence.json
- migrations/versions/0002_orchestration.py
- scripts/phase2a_migrate.py
- scripts/validate_phase2a.py
- scripts/validate_phase2a_tests.py
- src/ai_security_platform/api/pagination.py
- src/ai_security_platform/api/routes/snapshots.py
- src/ai_security_platform/cli/__init__.py
- src/ai_security_platform/cli/__main__.py
- src/ai_security_platform/cli/main.py
- src/ai_security_platform/domain/findings.py
- src/ai_security_platform/domain/intake.py
- src/ai_security_platform/jobs/__init__.py
- src/ai_security_platform/jobs/controller.py
- src/ai_security_platform/jobs/worker.py
- src/ai_security_platform/scanners/__init__.py
- src/ai_security_platform/scanners/contracts.py
- src/ai_security_platform/scanners/fake.py
- src/ai_security_platform/snapshots/__init__.py
- src/ai_security_platform/snapshots/filesystem.py
- src/ai_security_platform/snapshots/policy.py
- src/ai_security_platform/snapshots/store.py
- src/ai_security_platform/snapshots/windows.py
- src/ai_security_platform/storage/intake.py
- tests/native_windows_snapshots.py
- tests/postgres/test_intake.py
- tests/postgres/test_orchestration.py
- tests/unit/test_fake_and_cli.py
- tests/unit/test_snapshots.py

No files were staged or committed.
