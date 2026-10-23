# Phase 7 file inventory

Against the clean accepted Phase 6 starting worktree: **16 modified** and **73 created** public project files. No file was staged, committed or pushed. Paths are workspace-relative.

| Status | File | Purpose |
| --- | --- | --- |
| Modified | [.dockerignore](../../.dockerignore) | Allow only the additional nonsecret Phase 7 Compose test contract; preserve private-state and local-instruction exclusions. |
| Modified | [Dockerfile](../../Dockerfile) | Copy the nonsecret sandbox contract into the test stage so clean CI can enforce capability separation; runtime stage unchanged. |
| Modified | [README.md](../../README.md) | Finalize flagship status, entry points, quick start and explicit local capability limits. |
| Modified | [docs/PROJECT_BRIEF.md](../../docs/PROJECT_BRIEF.md) | Replace stale Phase 0 next-step text with current local flagship scope and final contracts. |
| Modified | [pyproject.toml](../../pyproject.toml) | Pin hatchling and six version/hash constraints for isolated builds; preserve runtime dependencies. |
| Modified | [runner/validate_isolation.py](../../runner/validate_isolation.py) | Select separate Phase 7 evidence/probe spool and propagate the selector to child probes. |
| Modified | [runner/validate_scanners.py](../../runner/validate_scanners.py) | Write independent Phase 7 real-scanner results using a controlled spool. |
| Modified | [src/ai_security_platform/reporting/files.py](../../src/ai_security_platform/reporting/files.py) | Bound and serialize artifact storage, preserve exclusive/interrupted publication and inspect safe usage. |
| Modified | [src/ai_security_platform/snapshots/store.py](../../src/ai_security_platform/snapshots/store.py) | Route abandoned staging removal through the hardened owned-tree deletion primitive. |
| Modified | [tests/native_windows_snapshots.py](../../tests/native_windows_snapshots.py) | Preserve historical reports while selecting independent Phase 7 native evidence. |
| Modified | [tests/unit/test_reporting_cli.py](../../tests/unit/test_reporting_cli.py) | Account for the persistent publication lock while preserving no-partial-artifact/no-overwrite assertions. |
| Modified | [uv.lock](../../uv.lock) | Record authenticated build constraints without changing existing locked package versions. |
| Modified | [web/playwright.config.ts](../../web/playwright.config.ts) | Separate Phase 7 private outputs and allow compiled preview from a trusted clean test context. |
| Modified | [web/tests/helpers.ts](../../web/tests/helpers.ts) | Read a phase-specific private browser fixture with Phase 6 as the backward-compatible default. |
| Modified | [web/tests/reporter.ts](../../web/tests/reporter.ts) | Write separate Phase 7 sanitized browser evidence and identify clean compiled preview. |
| Modified | [web/tests/security.spec.ts](../../web/tests/security.spec.ts) | Test denial of the selected phase-specific private probe file. |
| Created | [compose.phase7.yaml](../../compose.phase7.yaml) | Define guarded disposable services and explicitly exclude the launcher capability from ordinary/triage workers. |
| Created | [docs/phase7/ARCHITECTURE.md](../../docs/phase7/ARCHITECTURE.md) | Final implemented components, data flow, authority boundaries and Phase 7 decisions. |
| Created | [docs/phase7/COMMANDS.md](../../docs/phase7/COMMANDS.md) | Executed command ledger, corrected failures and local-versus-remote validation scope. |
| Created | [docs/phase7/COMPLETION-REPORT.md](../../docs/phase7/COMPLETION-REPORT.md) | All checkpoint/milestone decisions, versions, results, preservation, limitations and stop boundary. |
| Created | [docs/phase7/DEMONSTRATION.md](../../docs/phase7/DEMONSTRATION.md) | Safe retained-data walkthrough and honest interview/reproduction guidance. |
| Created | [docs/phase7/FILES.md](../../docs/phase7/FILES.md) | Exact public change inventory plus private/generated output classes. |
| Created | [docs/phase7/FINDINGS.md](../../docs/phase7/FINDINGS.md) | Severity/impact/reproduction/mitigation register, Trivy applicability and resource-observation investigation. |
| Created | [docs/phase7/PORTFOLIO.md](../../docs/phase7/PORTFOLIO.md) | Factual r?sum? statements and bounded evaluation/performance talking points. |
| Created | [docs/phase7/RETENTION-AND-RECOVERY.md](../../docs/phase7/RETENTION-AND-RECOVERY.md) | Ownership, reference/quota/cleanup, matched backup, integrity, instance and interruption contracts. |
| Created | [docs/phase7/RUNBOOK.md](../../docs/phase7/RUNBOOK.md) | Safe start/stop/restart, maintenance, fresh build, recovery and rollback procedures. |
| Created | [docs/phase7/THREAT-MODEL.md](../../docs/phase7/THREAT-MODEL.md) | Finished trust boundaries, attack controls, data lifecycle and residual risks. |
| Created | [docs/phase7/VALIDATION.md](../../docs/phase7/VALIDATION.md) | Complete measured results, performance denominators and genuine/scripted limits. |
| Created | [docs/phase7/acceptance.json](../../docs/phase7/acceptance.json) | Machine-readable G10/M4/checkpoint decision with evidence and scope. |
| Created | [docs/phase7/browser-evidence.json](../../docs/phase7/browser-evidence.json) | Nineteen final Chromium cases with live/security/scripted classification. |
| Created | [docs/phase7/build-toolchain.json](../../docs/phase7/build-toolchain.json) | Six exact build-package versions, official wheel hashes and dependency metadata. |
| Created | [docs/phase7/ci-evidence.json](../../docs/phase7/ci-evidence.json) | Seven offline clean-CI checks, 176 unit/API passes and no remote execution/upload. |
| Created | [docs/phase7/demo-evidence.json](../../docs/phase7/demo-evidence.json) | Eight genuine end-to-end controlled workflow/recovery checks, IDs, scanner provenance and explicit human history. |
| Created | [docs/phase7/dependency-advisories.json](../../docs/phase7/dependency-advisories.json) | Fifty public-version query results with the reviewed broad Trivy match preserved. |
| Created | [docs/phase7/dependency-audit.json](../../docs/phase7/dependency-audit.json) | Scoped npm audit result at validation time. |
| Created | [docs/phase7/environment-evidence.json](../../docs/phase7/environment-evidence.json) | 13 final clean/restored API, worker capability, privilege, ACL and scoped shutdown checks. |
| Created | [docs/phase7/examples/guardrails.json](../../docs/phase7/examples/guardrails.json) | Sanitized offline replay artifact sample from genuine frozen controlled observations; not a new scan or upload. |
| Created | [docs/phase7/examples/guardrails.sarif](../../docs/phase7/examples/guardrails.sarif) | Sanitized offline replay artifact sample from genuine frozen controlled observations; not a new scan or upload. |
| Created | [docs/phase7/examples/policy.json](../../docs/phase7/examples/policy.json) | Sanitized offline replay artifact sample from genuine frozen controlled observations; not a new scan or upload. |
| Created | [docs/phase7/final-static-evidence.json](../../docs/phase7/final-static-evidence.json) | Final Ruff, mypy, TypeScript and diff-check outcomes. |
| Created | [docs/phase7/frontend-command-evidence.json](../../docs/phase7/frontend-command-evidence.json) | Exit status of each guarded browser validation prerequisite and test command. |
| Created | [docs/phase7/frontend-evidence.json](../../docs/phase7/frontend-evidence.json) | Exact frontend versions/lock/asset hashes and ten confidentiality/auth/build checks. |
| Created | [docs/phase7/frontend-runtime.json](../../docs/phase7/frontend-runtime.json) | Observed final loopback listener, HTTP status and security headers. |
| Created | [docs/phase7/isolation-regression.json](../../docs/phase7/isolation-regression.json) | Thirty-one actual controlled Docker enforcement and cleanup checks. |
| Created | [docs/phase7/latest-restore-evidence.json](../../docs/phase7/latest-restore-evidence.json) | Seven latest-backup/fresh-instance/table/source/CLI verification checks. |
| Created | [docs/phase7/native-unit-evidence.json](../../docs/phase7/native-unit-evidence.json) | 53 native lifecycle/reporting passes, including the sandbox capability contract; overlap disclosed. |
| Created | [docs/phase7/performance-evidence.json](../../docs/phase7/performance-evidence.json) | Fixed-workload/process/resource/query-plan regression measurements. |
| Created | [docs/phase7/preview-evidence.json](../../docs/phase7/preview-evidence.json) | One actual compiled-preview/API browser result from the clean context. |
| Created | [docs/phase7/rebuild-evidence.json](../../docs/phase7/rebuild-evidence.json) | Fresh build commands, source hashes, final image ID and matching compiled asset digests. |
| Created | [docs/phase7/recovery-evidence.json](../../docs/phase7/recovery-evidence.json) | Actual process interruption/recovery and stale publication rejection observation. |
| Created | [docs/phase7/regression-comparison.json](../../docs/phase7/regression-comparison.json) | Ten frozen semantic/history/Git comparisons and investigated nonsemantic usage delta. |
| Created | [docs/phase7/restore-evidence.json](../../docs/phase7/restore-evidence.json) | Seventeen initial matched restore, corruption, missing-evidence and actual pg_restore recovery checks. |
| Created | [docs/phase7/retention-evidence.json](../../docs/phase7/retention-evidence.json) | Nine real reference/lock/quota/orphan and clean-worker checks with controlled test clock identified. |
| Created | [docs/phase7/review-1/README.md](../../docs/phase7/review-1/README.md) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/ci-evidence.json](../../docs/phase7/review-1/ci-evidence.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/environment-evidence.json](../../docs/phase7/review-1/environment-evidence.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/native-unit-evidence.json](../../docs/phase7/review-1/native-unit-evidence.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/performance-evidence.json](../../docs/phase7/review-1/performance-evidence.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/rebuild-evidence.json](../../docs/phase7/review-1/rebuild-evidence.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/regression-comparison.json](../../docs/phase7/review-1/regression-comparison.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/sandbox-capability-finding.json](../../docs/phase7/review-1/sandbox-capability-finding.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/supply-chain-evidence.json](../../docs/phase7/review-1/supply-chain-evidence.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/test-evidence.json](../../docs/phase7/review-1/test-evidence.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/review-1/triage-adversarial-evidence.json](../../docs/phase7/review-1/triage-adversarial-evidence.json) | Preserve first-review evidence before the sandbox capability fix; final root reports supersede it for G10/M4. |
| Created | [docs/phase7/runtime-evidence.json](../../docs/phase7/runtime-evidence.json) | 34 final runtime/preservation/capability checks, retained row counts and installed versions. |
| Created | [docs/phase7/sandbox-capability-evidence.json](../../docs/phase7/sandbox-capability-evidence.json) | Four actual container checks proving corrected sandbox and unchanged development worker capability separation. |
| Created | [docs/phase7/scanner-regression.json](../../docs/phase7/scanner-regression.json) | Sixteen genuine Semgrep/Trivy fixture/provenance/poisoning/coverage checks. |
| Created | [docs/phase7/storage-evidence.json](../../docs/phase7/storage-evidence.json) | Non-destructive retained source/report/backup storage and quota counts. |
| Created | [docs/phase7/supply-chain-evidence.json](../../docs/phase7/supply-chain-evidence.json) | Nine build/CI/image/DB provenance checks and source input hashes. |
| Created | [docs/phase7/test-evidence.json](../../docs/phase7/test-evidence.json) | 286 complete suite passes plus individual 25 scan/five triage crash experiments. |
| Created | [docs/phase7/triage-adversarial-evidence.json](../../docs/phase7/triage-adversarial-evidence.json) | Frozen deterministic/mocked quality/adversarial regression with timing/usage observations. |
| Created | [docs/phase7/trivy-advisory.json](../../docs/phase7/trivy-advisory.json) | Raw public OSV advisory kept for the documented applicability review. |
| Created | [docs/phase7/windows-filesystem-evidence.json](../../docs/phase7/windows-filesystem-evidence.json) | Ten administrator-run NTFS checks with no remaining blocked fixture. |
| Created | [scripts/lifecycle.py](../../scripts/lifecycle.py) | Implement trusted-host reference inspection, matched backup, bounded integrity verification and guarded disposable restoration. |
| Created | [scripts/maintenance.py](../../scripts/maintenance.py) | Expose narrow safe operator commands, explicit instance IDs and sanitized diagnostics. |
| Created | [scripts/prepare_phase7_browser.py](../../scripts/prepare_phase7_browser.py) | Select fresh controlled review fixtures without touching earlier evidence/history. |
| Created | [scripts/validate_phase7.py](../../scripts/validate_phase7.py) | Run complete guarded backend/PostgreSQL/process/evaluation regressions and collect Phase 7 evidence. |
| Created | [scripts/validate_phase7_assets.py](../../scripts/validate_phase7_assets.py) | Audit frontend assets/locks/auth/logs and all operator/sandbox credential absence. |
| Created | [scripts/validate_phase7_browser.py](../../scripts/validate_phase7_browser.py) | Run guarded locked install/build/Chromium/clean-preview validation sequentially. |
| Created | [scripts/validate_phase7_ci.py](../../scripts/validate_phase7_ci.py) | Validate current clean candidate CI artifacts and unit/API tests offline without remote workflow activation. |
| Created | [scripts/validate_phase7_demo.py](../../scripts/validate_phase7_demo.py) | Exercise a controlled genuine scan, explicit offline triage/review, reports/policy and restart recovery. |
| Created | [scripts/validate_phase7_environments.py](../../scripts/validate_phase7_environments.py) | Verify final clean/latest-restored APIs, restrictions, relationships and backup ACL, then stop owned disposable services. |
| Created | [scripts/validate_phase7_rebuild.py](../../scripts/validate_phase7_rebuild.py) | Create an allowlisted clean build context, rebuild application layers and compare compiled dashboard hashes. |
| Created | [scripts/validate_phase7_restore.py](../../scripts/validate_phase7_restore.py) | Exercise corruption, missing evidence, authenticated relationships and actual transactional restore termination/retry. |
| Created | [scripts/validate_phase7_retention.py](../../scripts/validate_phase7_retention.py) | Prove real PostgreSQL exclusion, reference preservation, orphan cleanup, quota recovery and clean offline workers. |
| Created | [scripts/validate_phase7_state.py](../../scripts/validate_phase7_state.py) | Preserve the pre-phase baseline and verify retained rows, credentials, schema and runtime restrictions. |
| Created | [scripts/validate_phase7_supply_chain.py](../../scripts/validate_phase7_supply_chain.py) | Check public advisory versions, hashed build inputs, official action commits and scanner asset identities. |
| Created | [src/ai_security_platform/snapshots/removal.py](../../src/ai_security_platform/snapshots/removal.py) | Implement whole-tree preflight and pinned NTFS / descriptor-relative POSIX cleanup. |
| Created | [tests/unit/test_lifecycle.py](../../tests/unit/test_lifecycle.py) | Exercise retention, backup integrity/quotas, filesystem hazards, target guards and safe maintenance arguments. |

## Ignored local state and generated files

- `.local/backups/phase7/`: two private matched bundles and ownership marker; no bundle contents are published, staged, built into images or uploaded.
- `.local/phase7-clean/`, `.local/phase7-restore/`, `.local/phase7-restore-<instance>/`: separate generated private credentials/spools for clean and recovery validation. All volumes/source/history are retained.
- `.local/phase7-probes/`, `.local/phase7-fixtures/`: maintained scanner test workspaces, separate from the retained source spool.
- `.local/snapshot-spool/`: one authorized controlled demonstration publication added; every earlier publication retained. No production cleanup was applied.
- `.local/reports/`: two controlled demo exports added; existing exports preserved. Publication now keeps one internal lock file.
- `.cache/phase7-*`: trusted receipts, first retention baseline, test/build/browser logs, guarded negative backup copies, clean source/dependency contexts and controlled fixtures. Negative copies can contain confidential source and remain private; never package the cache.
- `web/.env.phase7-probe`: harmless fixed marker for denial tests; no credential. `web/node_modules/` and `web/dist/` were reinstalled/rebuilt from the unchanged npm lock; three compiled assets match the clean build.
- `.venv/`: project metadata rebuilt after authenticated build constraints; existing runtime/dev package versions unchanged. Public package tool caches may contain approved dependency downloads.
- Existing ignored operator configuration temporarily enabled only controlled real scanning, then restored disabled admission. Credential values were preserved; hosted execution stayed disabled.

Earlier Phase 0?6 documents/evidence, frozen corpus/labels/methodology, scanner assets/policies, workflows, API/agent/scanner/queue/storage/schema modules and local instruction bytes remain unchanged. Global README/project brief now point to the finished local contracts.

Docker resource names and preserved-data evidence are in [the completion report](COMPLETION-REPORT.md), [recovery contract](RETENTION-AND-RECOVERY.md) and [environment evidence](environment-evidence.json). No unrelated repository/resource or Matroid file was modified.
