# Phase 6 file inventory

Compared with the clean Phase 6 starting worktree: **6 modified** and **51 created** files. No staging, commit or push occurred. Every path below is relative to the workspace.

| Status | File | Purpose |
| --- | --- | --- |
| Modified | [.gitignore](../../.gitignore) | Ignore browser output/report folders; preserve existing credential and instruction ignore rules. |
| Modified | [README.md](../../README.md) | Update Phase 6/G9 status and link dashboard setup, contracts and evidence. |
| Modified | [compose.yaml](../../compose.yaml) | Add only the exact loopback dashboard Origin to the API allowlist. |
| Modified | [runner/validate_isolation.py](../../runner/validate_isolation.py) | Add Phase 6 output/spool selection and child propagation; preserve isolation controls. |
| Modified | [runner/validate_scanners.py](../../runner/validate_scanners.py) | Add Phase 6 output/controlled-spool selection; preserve scanners and policies. |
| Modified | [tests/native_windows_snapshots.py](../../tests/native_windows_snapshots.py) | Write independent Phase 6 NTFS evidence without replacing accepted reports. |
| Created | [docs/phase6/ARCHITECTURE-AND-CONTRACTS.md](../../docs/phase6/ARCHITECTURE-AND-CONTRACTS.md) | Frontend boundary, exact dependencies, existing HTTP mapping, authentication, review and metrics semantics. |
| Created | [docs/phase6/COMMANDS.md](../../docs/phase6/COMMANDS.md) | Executed commands, scoped resource operations and corrected validation attempts. |
| Created | [docs/phase6/COMPLETION-REPORT.md](../../docs/phase6/COMPLETION-REPORT.md) | Checkpoint/G9 decisions, results, retained data, risks and unauthorized Phase 7 recommendation. |
| Created | [docs/phase6/FILES.md](../../docs/phase6/FILES.md) | Complete created/modified file inventory and ignored local-output classes. |
| Created | [docs/phase6/RUNBOOK.md](../../docs/phase6/RUNBOOK.md) | Private-token setup, start/test/restart, safe application rollback and preserved-data constraints. |
| Created | [docs/phase6/VALIDATION.md](../../docs/phase6/VALIDATION.md) | Evidence matrix, live-versus-scripted scope, corrected failures and validation limits. |
| Created | [docs/phase6/acceptance.json](../../docs/phase6/acceptance.json) | Machine-readable Phase 6 checkpoint/G9 determination with evidence references and limitations. |
| Created | [docs/phase6/browser-evidence.json](../../docs/phase6/browser-evidence.json) | Final 19-case Chromium report, including 11 actual persisted workflows. |
| Created | [docs/phase6/dependency-audit.json](../../docs/phase6/dependency-audit.json) | Scoped frontend npm audit at validation time; zero reported advisories. |
| Created | [docs/phase6/frontend-command-evidence.json](../../docs/phase6/frontend-command-evidence.json) | Exit status of all six sequential frontend validation commands. |
| Created | [docs/phase6/frontend-evidence.json](../../docs/phase6/frontend-evidence.json) | Exact dependency versions, lock/asset hashes and ten source/build/auth/confidentiality checks. |
| Created | [docs/phase6/frontend-runtime.json](../../docs/phase6/frontend-runtime.json) | Actual loopback listener/HTTP/security-header observation for the running local UI. |
| Created | [docs/phase6/isolation-regression.json](../../docs/phase6/isolation-regression.json) | 31 actual container-boundary checks and controlled probe identity. |
| Created | [docs/phase6/layout-evidence.json](../../docs/phase6/layout-evidence.json) | Five overlapping focused presentation/security regression results. |
| Created | [docs/phase6/performance-evidence.json](../../docs/phase6/performance-evidence.json) | Earlier accepted fixed-workload regression measurements and indexed query plans; no new capacity claim. |
| Created | [docs/phase6/preview-evidence.json](../../docs/phase6/preview-evidence.json) | Final compiled-preview browser result using the actual API. |
| Created | [docs/phase6/recovery-evidence.json](../../docs/phase6/recovery-evidence.json) | Real process termination/recovery and stale-write rejection regression observation. |
| Created | [docs/phase6/regression-comparison.json](../../docs/phase6/regression-comparison.json) | Six frozen outcome, prior-evidence, source, local-instruction and Git-boundary comparisons. |
| Created | [docs/phase6/runtime-evidence.json](../../docs/phase6/runtime-evidence.json) | 32 runtime/retention checks, installed versions, container restrictions and retained row counts. |
| Created | [docs/phase6/scanner-regression.json](../../docs/phase6/scanner-regression.json) | 16 genuine Semgrep/Trivy regression checks and scanner/DB provenance. |
| Created | [docs/phase6/test-evidence.json](../../docs/phase6/test-evidence.json) | 256 backend test outcomes plus 25 scan and five triage crash/retry experiments. |
| Created | [docs/phase6/triage-adversarial-evidence.json](../../docs/phase6/triage-adversarial-evidence.json) | Frozen deterministic/mocked-provider quality and attack regression output; no live model calls. |
| Created | [docs/phase6/windows-filesystem-evidence.json](../../docs/phase6/windows-filesystem-evidence.json) | Ten successful native Windows snapshot safety checks, including elevated symlink fixtures. |
| Created | [scripts/prepare_phase6_browser.py](../../scripts/prepare_phase6_browser.py) | Select existing controlled records and a fresh review target; prepare private fixture metadata safely. |
| Created | [scripts/validate_phase6.py](../../scripts/validate_phase6.py) | Run full guarded disposable PostgreSQL/backend/process/evaluation regressions and collect sanitized evidence. |
| Created | [scripts/validate_phase6_assets.py](../../scripts/validate_phase6_assets.py) | Verify locked assets, source practices, origin/authentication, known credential absence and scoped package audit. |
| Created | [scripts/validate_phase6_browser.py](../../scripts/validate_phase6_browser.py) | Sequential guarded prepare/install/build/browser/full/preview validation with sanitized private logs. |
| Created | [scripts/validate_phase6_state.py](../../scripts/validate_phase6_state.py) | Verify container restrictions, disabled admissions, versions and preservation of all pre-existing rows. |
| Created | [tests/api/test_browser_origin.py](../../tests/api/test_browser_origin.py) | Test the exact frontend Origin with existing bearer, preflight and denial contracts. |
| Created | [web/.npmrc](../../web/.npmrc) | Disable dependency installation hooks and require exact direct versions. |
| Created | [web/index.html](../../web/index.html) | Minimal application root and local module entry. |
| Created | [web/package-lock.json](../../web/package-lock.json) | Lock complete frontend dependency resolution and integrity metadata. |
| Created | [web/package.json](../../web/package.json) | Declare private frontend package, exact dependencies and local commands. |
| Created | [web/playwright.config.ts](../../web/playwright.config.ts) | Actual Chromium configuration, private browser cache, local dev/preview server and no credential-bearing captures. |
| Created | [web/src/App.tsx](../../web/src/App.tsx) | Authentication, project/history/scanner/finding navigation, filters and scoped metrics; preserve drafts during refresh. |
| Created | [web/src/Investigation.tsx](../../web/src/Investigation.tsx) | Explicit deterministic investigation, bounded polling, abstention/provenance and validated citation display. |
| Created | [web/src/Review.tsx](../../web/src/Review.tsx) | Confirmed human dispositions, notes/feedback, optimistic conflict handling and immutable history. |
| Created | [web/src/api.ts](../../web/src/api.ts) | Memory bearer, fixed API authority, bounded/sanitized requests and validated response metadata. |
| Created | [web/src/components.tsx](../../web/src/components.tsx) | Accessible shared controls, safe error handling and request-identity guards. |
| Created | [web/src/contracts.ts](../../web/src/contracts.ts) | Typed existing API records, pagination and review/triage contracts. |
| Created | [web/src/env.d.ts](../../web/src/env.d.ts) | Type the restricted Vite module environment. |
| Created | [web/src/main.tsx](../../web/src/main.tsx) | Mount React application and local styles. |
| Created | [web/src/styles.css](../../web/src/styles.css) | Responsive application shell, typography, forms and focus/status styling. |
| Created | [web/src/workspace.css](../../web/src/workspace.css) | Scanner/finding/investigation/review layouts and responsive detail styling. |
| Created | [web/tests/helpers.ts](../../web/tests/helpers.ts) | Trusted test-only configuration, API/browser fixtures and safe token entry; excluded from served client content. |
| Created | [web/tests/preview.spec.ts](../../web/tests/preview.spec.ts) | Compiled strict-CSP assets with actual API records and authenticated browser behavior. |
| Created | [web/tests/reporter.ts](../../web/tests/reporter.ts) | Sanitized machine-readable case outcomes with live/scripted scope classification. |
| Created | [web/tests/security.spec.ts](../../web/tests/security.spec.ts) | Origin/auth/content/credential/budget/security tests plus explicitly scripted hostile/failure scenarios. |
| Created | [web/tests/workflow.spec.ts](../../web/tests/workflow.spec.ts) | Actual API/PostgreSQL navigation, metrics, deterministic triage, review/conflict/history and responsive workflows. |
| Created | [web/tsconfig.json](../../web/tsconfig.json) | Strict TypeScript/browser and trusted test/config typechecking. |
| Created | [web/vite.config.ts](../../web/vite.config.ts) | Fixed loopback binding, Host/Origin checks, private-file denial and dev/preview security headers. |

## Ignored local outputs

- `web/node_modules/`, `web/dist/`: locked frontend dependencies and compiled assets; not committed or included in the backend Docker context.
- `web/.env.phase6-probe`: harmless fixed test marker used to prove private-file denial; no credential.
- `.cache/phase6-browsers/`: project-local Chromium/FFmpeg/Windows browser dependencies.
- `.cache/phase6-*`: private browser fixture IDs, first retention baseline, backend/frontend command logs and manual controlled-record visual captures. No published screenshots, browser traces or videos.
- `.local/phase6-probes/` and `.local/phase6-fixtures/`: isolated controlled scanner regression workspaces; original immutable snapshot spool remains preserved.

The existing development credential configuration was unchanged. API/worker backend source, Python dependency lock, migrations, scanner rules/images/databases, frozen evaluation labels/methodology and all earlier-phase documentation/evidence are unchanged. Local repository instructions remain ignored and read-only. No frontend credential or browser-storage persistence was added.

New controlled database records are documented in [the completion report](COMPLETION-REPORT.md); they are retained rather than cleared for repeatability. Disposable test database migration exercises used only the guarded test namespace and retained its volume.
