# Phase 7 validation and limits

G10/M4 and checkpoints 7A/7B/7C pass within the documented local Windows/Docker Desktop,
PostgreSQL, Chromium and deterministic/mocked-provider scope. No required local check is
blocked or silently skipped. Initial failures and their corrections are in [COMMANDS.md](COMMANDS.md).

| Executed group | Passed | Failed | Skipped/blocked | Evidence |
| --- | --- | --- | --- | --- |
| Complete API/unit/real PostgreSQL/process/evaluation suite | 286 | 0 | 0 | [test-evidence.json](test-evidence.json) |
| Native lifecycle/reporting subset | 53 | 0 | 0 | [native-unit-evidence.json](native-unit-evidence.json) |
| Native Windows snapshot protections | 10 | 0 | 0 | [windows-filesystem-evidence.json](windows-filesystem-evidence.json), operator administrator run |
| Actual scanner container containment | 31 | 0 | 0 | [isolation-regression.json](isolation-regression.json) |
| Genuine Semgrep/Trivy positive/clean/failure/poisoning checks | 16 | 0 | 0 | [scanner-regression.json](scanner-regression.json) |
| Actual Chromium full suite | 19 | 0 | 0 | [browser-evidence.json](browser-evidence.json): 11 live persisted workflows, three security contracts, five explicitly scripted scenarios |
| Compiled preview from clean context | 1 | 0 | 0 | [preview-evidence.json](preview-evidence.json), actual authenticated API records |
| Initial restore, corruption and interruption checks | 17 | 0 | 0 | [restore-evidence.json](restore-evidence.json) |
| Latest backup restored into fresh instance / CLI replay | 7 | 0 | 0 | [latest-restore-evidence.json](latest-restore-evidence.json) |
| Reference/lock/quota/cleanup and clean worker checks | 9 | 0 | 0 | [retention-evidence.json](retention-evidence.json) |
| Fresh build and identical compiled web artifacts | 4 | 0 | 0 | [rebuild-evidence.json](rebuild-evidence.json) |
| Final clean/restore APIs, privilege, ACL and scoped shutdown | 13 | 0 | 0 | [environment-evidence.json](environment-evidence.json) |
| Genuine end-to-end controlled demonstration | 8 | 0 | 0 | [demo-evidence.json](demo-evidence.json) |
| Supply-chain identity/locking/official action review | 9 | 0 | 0 | [supply-chain-evidence.json](supply-chain-evidence.json) |
| Frontend build/auth/confidentiality/log checks | 10 | 0 | 0 | [frontend-evidence.json](frontend-evidence.json) |
| Retained development data/runtime boundary | 34 | 0 | 0 | [runtime-evidence.json](runtime-evidence.json) |
| Frozen outcomes, historical evidence and Git boundaries | 10 | 0 | 0 | [regression-comparison.json](regression-comparison.json) |

The clean CI artifact fallback passed seven checks and 176 unit/API tests, additionally
validating JSON/SARIF generation without network,
credentials or target execution; its dedicated [CI report](ci-evidence.json) separates
local unit/API counts from the full real PostgreSQL run. Remote Actions/upload were not run.

Counts overlap: native subsets repeat backend cases; process experiments are included in
the 286 tests; repeated scanner/evaluation observations are not independent samples. Do not
sum rows into an inflated unique security-case total. Ruff, mypy (67 source files), strict
TypeScript, frozen installs/builds and final diff checks pass.

## Recovery, privacy and preservation

The full suite reran 25 scan crash/retry experiments (five each at claim/output/findings/
commit/DB interruption) and five triage recovery experiments with real PostgreSQL and
separate processes. Fenced findings/status/audit publication, idempotency, lease expiry,
retry exhaustion, partial outcomes, provider failure and human-review atomicity remain intact.

The first matched restore verified 18 table fingerprints and 13 registered sources. The
latest backup verified all 18 fingerprints and 14 registered sources, including completed
demo/browser history, in a fresh instance. Missing/corrupt/mismatched backups were rejected
before target changes. A real pg_restore backend was terminated during transactional DDL;
zero application tables remained after rollback, and retry restored the expected records.
Missing source produced explicit abstention and 409 export rejection; scanner records stayed
unchanged, and matching source was reinstated only in the disposable spool.

Retention tests use actual DB locks, NTFS files and deletion. Only the test clock advances
source eligibility. The pending registered source and all DB rows survive; only one
unregistered orphan in the disposable clean spool is removed. Native tests additionally
verify hardlink/junction/outside-file protection, unsupported Windows namespace rejection,
backup quotas/ownership and report quota/interruption/no-overwrite behavior.

Every pre-existing development row remains unchanged by fingerprint comparison across
17 application tables. Published source is preserved. [Storage inspection](storage-evidence.json)
records quotas and zero retained-source removals. Private ACLs restrict backup access to
operator/SYSTEM. Known operator/sandbox credentials are absent from changed public files,
bundles and inspected logs. Raw backups/full source are excluded from published evidence.
Heuristic redaction is not complete protection against arbitrary secret encodings.

## Evaluation and supply chain

Frozen quality/category, citation/support, disposition and adversarial results match Phase 6.
The 28-fixture / 14-held-out / 16-attack methodology and labels are unchanged. The complete
frozen scanner observations were replayed for deterministic quality regression; separate
actual scanner checks and the genuine 86-alert demo reran container execution. No new
independent-discovery or broad hosted-model quality claim is made.

The archived first review observed one context-byte/token change in an unsupported dependency
case; the final rerun has three one-byte resource differences across dependency/ungraded
Kubernetes cases. Existing stable_rows already excludes resource/timing observations. UUID-ordered peer
context after reacquisition is a plausible explanation; raw context is not exported, so
that explanation is labelled an inference. All semantic/support outcomes match. A13 unsafe
advisory semantics and the two ungraded Kubernetes bindings remain unchanged.

Public-version OSV review queried 50 unique ecosystem/name/version tuples, including six
hashed build constraints. One broad Trivy range match is retained and assessed against the
upstream advisory in [FINDINGS.md](FINDINGS.md). The sandbox worker capability inheritance was corrected and verified with a new static
contract plus actual containers; the first review remains in `review-1/`.
The scoped npm audit reports zero advisories
at validation time. Scanner image/DB identity and official pinned CI commits are verified;
this is not a complete transitive image SBOM or publisher-signature assurance claim.

## Fixed workload observations

Same established local host/Docker resources; other applications were not stopped. These
are diagnostic regressions, not production capacity, SLOs or controlled performance gains.
200 marker files / 6,030 bytes; six runs, 12 scans and 24 jobs/run; 72 scans, 144 jobs,
15,120 synthetic findings total. Cache labels mean execution order; caches were not flushed.
Shared host load, process startup and growing disposable tables remain confounders.

| Workers | Order | Jobs/s | Queue p50/p95 ms | Execution p50/p95 ms | Lifecycle p50/p95 ms |
| --- | --- | --- | --- | --- | --- |
| 1 | first_publication_execution | 10.66 | 4132.66 / 4814.78 | 25.84 / 104.00 | 4157.40 / 4881.66 |
| 1 | repeated_warm | 11.49 | 3944.11 / 4527.78 | 23.86 / 65.25 | 3965.41 / 4590.29 |
| 2 | first_publication_execution | 15.89 | 4001.89 / 4404.48 | 25.31 / 131.56 | 4040.45 / 4517.87 |
| 2 | repeated_warm | 15.31 | 3859.75 / 4281.97 | 27.20 / 91.80 | 3895.39 / 4341.26 |
| 4 | first_publication_execution | 20.76 | 3943.41 / 4117.95 | 34.73 / 106.64 | 4025.59 / 4217.19 |
| 4 | repeated_warm | 22.26 | 3838.35 / 4022.30 | 28.48 / 94.01 | 3865.64 / 4056.19 |

Finding query n=30: p50 **2.483 ms**, p95 **3.794 ms**.
History query n=30: p50 **1.360 ms**, p95 **1.942 ms**.
Actual query plans/buffers and per-worker CPU/peak RSS are in
[performance-evidence.json](performance-evidence.json). No new index was necessary.
The genuine 86-alert demo is a different input from Phase 5's 85-alert workload and is not
a detection/performance improvement comparison.

Chromium-only coverage, focused accessibility, trusted local host/browser, conservative
history retention, separate scanner asset requirements and no live hosted validation remain
explicit. See [the final threat model](THREAT-MODEL.md) for the complete scope and residual risk.
