# Phase 2B changed-file inventory

25 modified existing files and 65 created deliverables (90 total). Paths are relative to the repository root. Nothing is staged. Ignored local configuration, scanner DB assets, validation snapshots, caches and the private migration backup are intentionally absent; no credentials or local instructions are listed as deliverables.

| File | Change | Purpose |
| --- | --- | --- |
| [.dockerignore](../../.dockerignore) | Modified | Package trusted registry; keep host launcher, instructions and private files outside application context |
| [Dockerfile](../../Dockerfile) | Modified | Package trusted registry; keep host launcher, instructions and private files outside application context |
| [README.md](../../README.md) | Modified | Current Phase 2B status and documentation links |
| [compose.yaml](../../compose.yaml) | Modified | Independent API launcher capability and opt-in real admission; no daemon privileges |
| [pyproject.toml](../../pyproject.toml) | Modified | Stable Ruff first-party classification across host and restricted container context |
| [scripts/bootstrap_local.py](../../scripts/bootstrap_local.py) | Modified | Secure independent launcher credential bootstrap; preserve existing configuration |
| [src/ai_security_platform/api/app.py](../../src/ai_security_platform/api/app.py) | Modified | Independent launcher capability, fenced handoff, finding detail/export and preserved public boundary |
| [src/ai_security_platform/api/routes/scan_runs.py](../../src/ai_security_platform/api/routes/scan_runs.py) | Modified | Independent launcher capability, fenced handoff, finding detail/export and preserved public boundary |
| [src/ai_security_platform/api/security.py](../../src/ai_security_platform/api/security.py) | Modified | Independent launcher capability, fenced handoff, finding detail/export and preserved public boundary |
| [src/ai_security_platform/cli/main.py](../../src/ai_security_platform/cli/main.py) | Modified | Explicit real/fake profile choice; snapshot output reflects admission requirement |
| [src/ai_security_platform/config.py](../../src/ai_security_platform/config.py) | Modified | Typed opt-in real-scanner settings and independent launcher capability |
| [src/ai_security_platform/domain/findings.py](../../src/ai_security_platform/domain/findings.py) | Modified | Typed real-scan/evidence/coverage and narrow host capability contracts |
| [src/ai_security_platform/domain/intake.py](../../src/ai_security_platform/domain/intake.py) | Modified | Typed real-scan/evidence/coverage and narrow host capability contracts |
| [src/ai_security_platform/domain/scans.py](../../src/ai_security_platform/domain/scans.py) | Modified | Typed real-scan/evidence/coverage and narrow host capability contracts |
| [src/ai_security_platform/jobs/controller.py](../../src/ai_security_platform/jobs/controller.py) | Modified | Durable real-scanner handoff with bounded heartbeats and fenced publication |
| [src/ai_security_platform/jobs/worker.py](../../src/ai_security_platform/jobs/worker.py) | Modified | Durable real-scanner handoff with bounded heartbeats and fenced publication |
| [src/ai_security_platform/scanners/contracts.py](../../src/ai_security_platform/scanners/contracts.py) | Modified | Trusted registry, bounded typed adapters and sanitized real output normalization |
| [src/ai_security_platform/storage/base.py](../../src/ai_security_platform/storage/base.py) | Modified | Current schema, generation-unique handoffs, registry-bound acceptance and fenced staging |
| [src/ai_security_platform/storage/intake.py](../../src/ai_security_platform/storage/intake.py) | Modified | Current schema, generation-unique handoffs, registry-bound acceptance and fenced staging |
| [src/ai_security_platform/storage/models.py](../../src/ai_security_platform/storage/models.py) | Modified | Current schema, generation-unique handoffs, registry-bound acceptance and fenced staging |
| [tests/api/test_contracts.py](../../tests/api/test_contracts.py) | Modified | HTTP/normalization/coverage/handoff and PostgreSQL regression coverage |
| [tests/native_windows_snapshots.py](../../tests/native_windows_snapshots.py) | Modified | Separate Phase 2B evidence destination; preserve accepted Phase 2A proof |
| [tests/postgres/conftest.py](../../tests/postgres/conftest.py) | Modified | HTTP/normalization/coverage/handoff and PostgreSQL regression coverage |
| [tests/postgres/test_database.py](../../tests/postgres/test_database.py) | Modified | HTTP/normalization/coverage/handoff and PostgreSQL regression coverage |
| [tests/unit/test_settings.py](../../tests/unit/test_settings.py) | Modified | HTTP/normalization/coverage/handoff and PostgreSQL regression coverage |
| [docs/phase2b/API-AND-SCHEMA.md](../../docs/phase2b/API-AND-SCHEMA.md) | Created | Phase 2B contracts, operational guidance and completion evidence |
| [docs/phase2b/ARCHITECTURE.md](../../docs/phase2b/ARCHITECTURE.md) | Created | Phase 2B contracts, operational guidance and completion evidence |
| [docs/phase2b/COMMANDS.md](../../docs/phase2b/COMMANDS.md) | Created | Phase 2B contracts, operational guidance and completion evidence |
| [docs/phase2b/COMPLETION-REPORT.md](../../docs/phase2b/COMPLETION-REPORT.md) | Created | Phase 2B contracts, operational guidance and completion evidence |
| [docs/phase2b/FILES.md](../../docs/phase2b/FILES.md) | Created | Phase 2B contracts, operational guidance and completion evidence |
| [docs/phase2b/RUNBOOK.md](../../docs/phase2b/RUNBOOK.md) | Created | Phase 2B contracts, operational guidance and completion evidence |
| [docs/phase2b/isolation-evidence.json](../../docs/phase2b/isolation-evidence.json) | Created | Sanitized executed validation/provenance evidence |
| [docs/phase2b/live-evidence.json](../../docs/phase2b/live-evidence.json) | Created | Sanitized executed validation/provenance evidence |
| [docs/phase2b/migration-evidence.json](../../docs/phase2b/migration-evidence.json) | Created | Sanitized executed validation/provenance evidence |
| [docs/phase2b/runtime-evidence.json](../../docs/phase2b/runtime-evidence.json) | Created | Sanitized executed validation/provenance evidence |
| [docs/phase2b/scanner-evidence.json](../../docs/phase2b/scanner-evidence.json) | Created | Sanitized executed validation/provenance evidence |
| [docs/phase2b/test-evidence.json](../../docs/phase2b/test-evidence.json) | Created | Sanitized executed validation/provenance evidence |
| [docs/phase2b/windows-filesystem-evidence.json](../../docs/phase2b/windows-filesystem-evidence.json) | Created | Sanitized executed validation/provenance evidence |
| [migrations/versions/0003_scanner_handoff.py](../../migrations/versions/0003_scanner_handoff.py) | Created | Forward-only retained-data extension; guarded disposable downgrade |
| [policies/README.md](../../policies/README.md) | Created | Immutable scanner/policy/executable/DB provenance and refresh contract |
| [policies/scanners.lock.json](../../policies/scanners.lock.json) | Created | Immutable scanner/policy/executable/DB provenance and refresh contract |
| [runner/__init__.py](../../runner/__init__.py) | Created | Host-only fixed-profile launcher, image/DB preparation or real container gate validation |
| [runner/boundary.py](../../runner/boundary.py) | Created | Host-only fixed-profile launcher, image/DB preparation or real container gate validation |
| [runner/images/probe/.dockerignore](../../runner/images/probe/.dockerignore) | Created | Trusted controlled isolation/resource-exhaustion probe and isolated build context |
| [runner/images/probe/Dockerfile](../../runner/images/probe/Dockerfile) | Created | Trusted controlled isolation/resource-exhaustion probe and isolated build context |
| [runner/images/probe/probe.py](../../runner/images/probe/probe.py) | Created | Trusted controlled isolation/resource-exhaustion probe and isolated build context |
| [runner/images/semgrep/.dockerignore](../../runner/images/semgrep/.dockerignore) | Created | Pinned Semgrep image, first-party rules and trusted bounded audit view |
| [runner/images/semgrep/Dockerfile](../../runner/images/semgrep/Dockerfile) | Created | Pinned Semgrep image, first-party rules and trusted bounded audit view |
| [runner/images/semgrep/rules.yaml](../../runner/images/semgrep/rules.yaml) | Created | Pinned Semgrep image, first-party rules and trusted bounded audit view |
| [runner/images/semgrep/wrapper.py](../../runner/images/semgrep/wrapper.py) | Created | Pinned Semgrep image, first-party rules and trusted bounded audit view |
| [runner/images/trivy/.dockerignore](../../runner/images/trivy/.dockerignore) | Created | Pinned Trivy image, fixed offline policy and trusted bounded audit view |
| [runner/images/trivy/Dockerfile](../../runner/images/trivy/Dockerfile) | Created | Pinned Trivy image, fixed offline policy and trusted bounded audit view |
| [runner/images/trivy/empty.ignore](../../runner/images/trivy/empty.ignore) | Created | Pinned Trivy image, fixed offline policy and trusted bounded audit view |
| [runner/images/trivy/secret.yaml](../../runner/images/trivy/secret.yaml) | Created | Pinned Trivy image, fixed offline policy and trusted bounded audit view |
| [runner/images/trivy/trivy.yaml](../../runner/images/trivy/trivy.yaml) | Created | Pinned Trivy image, fixed offline policy and trusted bounded audit view |
| [runner/images/trivy/wrapper.py](../../runner/images/trivy/wrapper.py) | Created | Pinned Trivy image, fixed offline policy and trusted bounded audit view |
| [runner/launcher.py](../../runner/launcher.py) | Created | Host-only fixed-profile launcher, image/DB preparation or real container gate validation |
| [runner/prepare.py](../../runner/prepare.py) | Created | Host-only fixed-profile launcher, image/DB preparation or real container gate validation |
| [runner/validate_isolation.py](../../runner/validate_isolation.py) | Created | Host-only fixed-profile launcher, image/DB preparation or real container gate validation |
| [runner/validate_scanners.py](../../runner/validate_scanners.py) | Created | Host-only fixed-profile launcher, image/DB preparation or real container gate validation |
| [scripts/phase2b_migrate.py](../../scripts/phase2b_migrate.py) | Created | Guarded Phase 2B migration or reproducible local validation harness |
| [scripts/validate_phase2b_live.py](../../scripts/validate_phase2b_live.py) | Created | Guarded Phase 2B migration or reproducible local validation harness |
| [scripts/validate_phase2b_state.py](../../scripts/validate_phase2b_state.py) | Created | Guarded Phase 2B migration or reproducible local validation harness |
| [scripts/validate_phase2b_tests.py](../../scripts/validate_phase2b_tests.py) | Created | Guarded Phase 2B migration or reproducible local validation harness |
| [src/ai_security_platform/api/routes/findings.py](../../src/ai_security_platform/api/routes/findings.py) | Created | Independent launcher capability, fenced handoff, finding detail/export and preserved public boundary |
| [src/ai_security_platform/api/routes/launcher.py](../../src/ai_security_platform/api/routes/launcher.py) | Created | Independent launcher capability, fenced handoff, finding detail/export and preserved public boundary |
| [src/ai_security_platform/domain/launcher.py](../../src/ai_security_platform/domain/launcher.py) | Created | Typed real-scan/evidence/coverage and narrow host capability contracts |
| [src/ai_security_platform/scanners/real.py](../../src/ai_security_platform/scanners/real.py) | Created | Trusted registry, bounded typed adapters and sanitized real output normalization |
| [src/ai_security_platform/scanners/registry.py](../../src/ai_security_platform/scanners/registry.py) | Created | Trusted registry, bounded typed adapters and sanitized real output normalization |
| [src/ai_security_platform/storage/launcher.py](../../src/ai_security_platform/storage/launcher.py) | Created | Current schema, generation-unique handoffs, registry-bound acceptance and fenced staging |
| [tests/fixtures/scanners/clean/.github/workflows/ci.yml](../../tests/fixtures/scanners/clean/.github/workflows/ci.yml) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/clean/Dockerfile](../../tests/fixtures/scanners/clean/Dockerfile) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/clean/app.js](../../tests/fixtures/scanners/clean/app.js) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/clean/app.py](../../tests/fixtures/scanners/clean/app.py) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/clean/requirements.txt](../../tests/fixtures/scanners/clean/requirements.txt) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/.github/workflows/ci.yml](../../tests/fixtures/scanners/positive/.github/workflows/ci.yml) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/.semgrep.yml](../../tests/fixtures/scanners/positive/.semgrep.yml) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/.semgrepignore](../../tests/fixtures/scanners/positive/.semgrepignore) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/.trivyignore](../../tests/fixtures/scanners/positive/.trivyignore) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/Dockerfile](../../tests/fixtures/scanners/positive/Dockerfile) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/app.js](../../tests/fixtures/scanners/positive/app.js) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/app.py](../../tests/fixtures/scanners/positive/app.py) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/package-lock.json](../../tests/fixtures/scanners/positive/package-lock.json) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/package.json](../../tests/fixtures/scanners/positive/package.json) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/pod.yaml](../../tests/fixtures/scanners/positive/pod.yaml) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/requirements.txt](../../tests/fixtures/scanners/positive/requirements.txt) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/fixtures/scanners/positive/trivy.yaml](../../tests/fixtures/scanners/positive/trivy.yaml) | Created | Inert labelled scanner input; never imported, built or executed |
| [tests/postgres/test_launcher.py](../../tests/postgres/test_launcher.py) | Created | HTTP/normalization/coverage/handoff and PostgreSQL regression coverage |
| [tests/unit/test_coverage_limits.py](../../tests/unit/test_coverage_limits.py) | Created | HTTP/normalization/coverage/handoff and PostgreSQL regression coverage |
| [tests/unit/test_real_normalization.py](../../tests/unit/test_real_normalization.py) | Created | HTTP/normalization/coverage/handoff and PostgreSQL regression coverage |

