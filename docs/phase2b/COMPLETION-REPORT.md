# Phase 2B completion report

Phase 2B delivers the local AppSec scanning milestone: a separate trusted Windows
launcher, isolated pinned Semgrep/Trivy execution, bounded sanitized real findings,
independent coverage/provenance and durable lease-fenced publication. The approved
1Password AppSec priority is preserved, with secure policy automation and reliable
backend recovery supporting the Brain Co/Prophet overlap. No Phase 3 work was begun.

## Gates and validation

| Gate/checkpoint | Status | Executed evidence |
| --- | --- | --- |
| 2B-I / G4 launcher isolation | PASS on this Windows/Docker Desktop host | [31 real controlled-container checks](isolation-evidence.json), separate-capability PostgreSQL tests, [live ownership/recovery checks](live-evidence.json) |
| 2B-II / G5 real scanner integration | PASS for declared supported scope | [16 genuine scanner fixture checks](scanner-evidence.json), real API/worker pipeline and partial-results proof |
| Relevant G1/G2/G3 regressions | PASS | [165 pytest cases, 0 failed, 0 skipped; all 25 crash experiments](test-evidence.json), migration lifecycle, constraints, authentication, idempotency, pagination, snapshots, heartbeats/fencing |
| Native unit/API | PASS | 97 passed, 68 deliberately deselected PostgreSQL cases, 0 failed, 0 skipped; Python 3.12.15 on Windows |
| Native Windows filesystem boundary | PASS | [10 checks, 0 failed/blocked/skipped](windows-filesystem-evidence.json), operator administrator run |
| Actual API/worker/DB lifecycle | PASS | [10 live checks, 0 failed/skipped](live-evidence.json) with real scanner containers |
| Final local runtime/security state | PASS | [20 read-only checks](runtime-evidence.json), including build exclusions, private credentials absent from changed files and daemon authority absent from API/worker |
| Locked install / Ruff / format / mypy | PASS | `uv lock --check`, `uv sync --frozen`, Ruff clean, 91 Python files formatted, mypy 49 source files |

Counts are separate overlapping suites, not additive totals. PostgreSQL integration
cases were actually run in their dedicated container/database, not skipped on Windows.
One upstream Starlette TestClient deprecation warning is retained. G4 is a local
validated containment gate, not production certification or proof against kernel bugs.
There is no controlled-fixture fallback being presented as unrestricted isolation.
Real admission is deliberately disabled in final local configuration; enable only
through the verified [runbook](RUNBOOK.md).

## Implemented boundary and delivery

See [architecture](ARCHITECTURE.md) for trust assumptions and ownership sequence, and
[API/schema contracts](API-AND-SCHEMA.md) for precise deltas. API/ordinary workers never
receive Docker access. Only the host launcher uses the fixed local Docker Desktop pipe.
It accepts opaque source/attempt identities and fixed profile names, resolves immutable
images and trusted policy, verifies snapshots and enforces bounded disposable containers.
An independent bearer and exclusive private host lock protect the launcher protocol.

Scanner runtime uses non-root UID 10001, no network, read-only root/source, dropped
capabilities, no-new-privileges, CPU/memory/PID/file/tmp/output/deadline limits, no daemon
mount, no credentials and no writable host output mount. Controlled probes observed
network/DNS denial, source/root write denial, credential/socket denial, kernel resource
limits, memory OOM exit 137, process/temp exhaustion, output/time termination and scoped
orphan cleanup. Resource exhaustion is exercised at smaller controlled limits through
the same boundary implementation; real profiles use the fixed 1 CPU/1024 MiB/64 PID
limits documented in architecture. Tests reject extra mount/image/command/argv fields,
profile injection, invalid source identity and mutable image references.

Workers retain ownership and independent heartbeats. API staging and worker publication
both revalidate the current lease under job-first locks; only the worker's fenced
transaction publishes authoritative findings/status/audit. Real expiry recovered at
generation 2, produced exactly one completion event and rejected the stale result with
409. Killing the actual host launcher left an observable owned orphan; replacement
cleanup/reconciliation and durable retry completed successfully. API/worker/DB restarts
preserved results and the same processes recovered after the database returned.

## Measured detection and incomplete outcomes

| Maintained inert fixture | Semgrep | Trivy |
| --- | --- | --- |
| Labelled positive, including repository suppression/config poisoning | 8 findings: Python 3, JavaScript 3, CI 2 | 78 findings: 53 dependency advisories, 24 Dockerfile/Kubernetes misconfigurations, 1 synthetic secret |
| Labelled clean | 0 findings in declared execution scope | 0 findings in declared execution scope |
| Positive plus genuine malformed rule-relevant Python | Failed/incomplete coverage with valid findings retained | Successful independent slot; findings retained |
| Opaque unsupported input | Explicit incomplete/no supported targets | Explicit incomplete/no supported targets |
| Truncated genuine scanner JSON | Rejected | Rejected |
| Missing vulnerability DB | Not applicable | Actual container exits unsuccessfully; never clean |
| Stale DB metadata | Not applicable | Preflight denied; no expired coverage accepted |

The real pipeline persisted 86 sanitized positive findings. The parser-error fixture
persisted 87 findings and parent `partial`, with Semgrep `incomplete_coverage` and
allowlisted `scanner_errors`/`scanner_exit_failure` reasons, independently successful
Trivy and retained SAST/dependency findings. The added valid `eval` occurrence explains
the extra finding; source was never executed. Detailed rule/CVE/path sets and exact
provenance are in the scanner/live artifacts. These are small labelled functional
fixtures, not a statistically meaningful accuracy benchmark or a claim of universal
detection. A finding requires human assessment; dependency advisories do not establish
reachability. Zero findings means only no observed matches within recorded coverage.

Repository `.gitignore`, `.semgrepignore`, poisoned Semgrep/Trivy configurations,
`.trivyignore`, inline `nosemgrep` and inline Trivy suppression could not override the
trusted audit policy. The derived audit view excludes policy files and neutralizes
Trivy suppression tokens while preserving original snapshots/line positions. CI
checks use Semgrep YAML rules because this Trivy release lacks an Actions parser.
Raw scanner messages, snippets, secret Match/Code values and raw output are not stored.
Synthetic credential values and actual local credentials were absent from normalized
findings, exports and API/worker/launcher logs. Changed-file disclosure checks also
passed. Default redacted metadata is intentionally narrower than a complete secret DLP.

## Versions, rules and vulnerability database

| Component | Exact version |
| --- | --- |
| Python / uv | 3.12.15 / 0.13.5 |
| FastAPI / Pydantic / pydantic-settings | 0.161.0 / 2.14.1 / 2.16.1 |
| SQLAlchemy / Alembic / Psycopg (+ binary) | 2.0.55 / 1.20.1 / 3.3.6 |
| PostgreSQL | 17.11, Debian 17.11-1.pgdg12+2 |
| Semgrep / Trivy | 1.179.0 / 0.76.1 |
| Adapter / derived view / scanner profile | real-1 / audit-view-v1 / security-v1 |
| Ruff / mypy / pytest / HTTPX | 0.17.2 / 1.20.2 / 9.1.1 / 0.28.1 |
| Docker Desktop Linux engine / Compose | 29.9.1 / 5.6.0 |

All installed Python distribution versions are enumerated in `runtime-evidence.json`;
`uv.lock` is unchanged and remains the reproducibility authority. No runtime dependency
or infrastructure product was added. Host tooling reuses the existing dotenv package.

Exact official upstream manifests, prepared local image IDs, executable/core hashes,
trusted rule/config hashes and DB metadata are in
[the scanner registry](../../policies/scanners.lock.json). Current prepared images:

- Semgrep: `sha256:08d17ceb2851b3e9eabb31ab966c6b6c98574473d3edca5b818e5c45473e9311`.
- Trivy: `sha256:8d6faeff42dd93b2056c8ed084610fb22120f6c95a056a7edd41e89479ee585d`.
- Semgrep trusted policy SHA256: `12e58502b265a95d69709ae83cc4569c6b4d35b8d8873a6c51de5a57551e0fca`.
- Trivy trusted policy SHA256: `71bcd0217e6dbc4facca3abcc72fbbbec71946a102153f5e95ab00caf8768082`.
- Trivy DB schema 2, UpdatedAt `2026-10-22T19:14:47.059491382Z`, recorded as about
  six hours old during final scanner/live validation, maximum accepted age 48 hours.
- DB bundle SHA256: `4566427d61ff4e2c565b331376b07e58afc5166efd4a78cdc8fd10ca657d2898`.
  The registry separately pins the actual DB and metadata file hashes and timestamp.

Semgrep uses eight platform-authored rules, not a downloaded mutable commercial pack.
Trivy uses pinned executable-embedded Dockerfile/Kubernetes checks and a platform
secret rule. [Policy notes and primary references](../../policies/README.md) explain
scanner-specific choices. Images and DB are prepared separately with network access;
execution is offline. Historical pins must be retained for accepted-work provenance.

## Schema, compatibility and persistence

Forward revision `0003_scanner_handoff` extends existing data with scanner provenance,
safe finding evidence/synthetic identity and generation-unique fenced handoffs plus
launcher capability records. Defaults preserve accepted fake history. Existing fake-v1
adapters, acceptance/idempotency, constraints and pagination remain diagnostic paths.
The CLI adds explicit profile selection; snapshot output now says admission is required
instead of incorrectly claiming all scanning is synthetic. JSON finding detail/export
follow the approved Phase 0 scanner MVP contract; no SARIF or external upload was added.

[Migration evidence](migration-evidence.json) records a 36,001-byte private backup and
unchanged retained counts: projects 5, snapshots 2, scans 4, audit events 27, scanner
runs/jobs/attempts/findings 8 each, idempotency records 4. No development reset, destructive
downgrade or spool deletion occurred. Fresh/repeatable migration, metadata drift and
guarded disposable downgrade/re-upgrade passed against real PostgreSQL. Actual container
restarts preserved the newly stored real scan/findings. This is not a full restore drill.

## Files, commands and corrections

[FILES.md](FILES.md) lists every created/modified deliverable and purpose. Ignored local
configuration, scanner assets, fixture snapshots, diagnostics and backup remain private;
no secret values are included. [COMMANDS.md](COMMANDS.md) records actual command families
and reproducible harnesses, including the operator-admin native check. Historical Phase
0/1/2A documents/evidence are preserved. No Git staging/commits/pushes or remote activation.

Development corrections are disclosed in the command record: actual upstream executable
paths, prefiltered malformed-source behavior, sequential Docker harness ownership,
consistent host/container Ruff import classification, and the warning-list HTTP schema.
The native privilege check was blocked until the operator's successful administrator
run. Current final artifacts reflect passing reruns; no mandatory check was converted
to a mock or silently skipped, and no security requirement was relaxed.

## Limitations and risks

- Scope is selected SAST patterns, pinned Python/npm advisory checks, one synthetic
  secret family and Dockerfile/Kubernetes/CI guardrails. Terraform, arbitrary languages,
  every ecosystem/lockfile, image-content scans and online dependency resolution are
  unsupported/unvalidated. Recognized gaps are marked incomplete; unfamiliar formats
  are not guaranteed to be classified. No comprehensive detection claim is made.
- Docker Desktop/host/kernel, official image supply chain, trusted policy and the
  privileged local account remain trusted. Digest pinning verifies identity, not
  absence of scanner vulnerabilities. No hostile multi-tenant deployment is supported.
- A dead/unreachable Docker daemon can delay cleanup until operator recovery. New
  intake fails closed; restart reconciliation removes only owned scanner containers.
  Abrupt launcher death needs restart reconciliation; there is no independent Docker
  TTL. Bounded control/daemon calls add latency to the 90-second execution budget.
  Do not run independent Docker validation harnesses concurrently with the launcher.
- One sequential launcher is intentionally bounded, not a general orchestration
  platform. Complete/incomplete findings require human interpretation. Cross-scan
  fingerprints are heuristic and can change with renames/semantic changes.
- DB age expires after 48 hours. Refresh changes accepted policy identity and requires
  coordinated rebuild/revalidation. Older queued policy resolution fails visibly
  rather than silently switching versions; a multi-version catalog is future work.
- Existing snapshot quotas/24-hour admission retention and no published-snapshot GC
  remain. Assets/results/backups also require careful operator retention; this phase
  adds no destructive automatic cleanup. Repeated validation retains data by design.
- Local bearer auth, a single operator and shared trusted service DB privileges remain
  the approved boundary. Redaction removes scanner excerpts/secret values by design,
  but arbitrary metadata/filenames can still require confidentiality review.
- The existing CI definition does not prove Windows isolation or scanner availability.
  Required local G4/G5 evidence must be repeated after relevant environment changes.

There are no unresolved Phase 2B gate blockers within this declared scope. The selected
CI scanner choice and explicitly unsupported formats are scope decisions, not broader
infrastructure/stack substitutions. No AI, hosted model, review/remediation, dashboard,
SOC, general shell proxy, Kubernetes or Matroid change was implemented.

## Safe operational handoff

Follow [RUNBOOK.md](RUNBOOK.md) for restart and rollback: disable real admission,
stop only the project worker/launcher, reconcile exact owned containers, preserve DB,
spool/assets/images/history, and prefer compatible forward fixes. Never downgrade retained
data, prune Docker or clear volumes. Final local API/DB/worker remain available with
real intake disabled, scanner/launcher stopped, and test DB stopped without deletion.

Recommended **Phase 3, NOT AUTHORIZED**: begin from these read-only finding/provenance
contracts; implement the approved bounded evidence agent and optimistic-concurrency
human review with deterministic provider, citation/abstention/budget safety tests and
separately opt-in hosted consent. Reconfirm G4/G5 environment freshness before using
new source. Do not add scanner/launcher control as an agent tool. Phase 4 evaluation
expansion and optional Prophet SOC remain separately authorized later milestones.
